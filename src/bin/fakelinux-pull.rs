//! Minimal OCI image puller — pulls Docker/OCI images without Docker installed.
//! Usage: fakelinux-pull <image:tag> <output-dir>
//!
//! Supports Docker Hub (docker.io) and GitHub Container Registry (ghcr.io).

use reqwest::blocking::Client;
use serde_json::Value;
use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <image:tag> <output-dir>", args[0]);
        eprintln!("Example: {} python:3.12-alpine ./python-rootfs", args[0]);
        eprintln!("         {} ghcr.io/owner/repo:tag ./rootfs", args[0]);
        std::process::exit(1);
    }

    let (registry, image, tag) = parse_image_ref(&args[1]);
    let output_dir = &args[2];

    println!("Pulling {registry}/{image}:{tag} -> {output_dir}");

    let client = Client::builder()
        .user_agent("fakelinux-pull/0.1")
        .build()
        .expect("failed to build HTTP client");

    // Step 1: Get auth token
    println!("Authenticating with {registry}...");
    let token = get_auth_token(&client, &registry, &image);

    // Step 2: Fetch manifest (handle fat manifests / OCI indices)
    println!("Fetching manifest...");
    let manifest = get_manifest(&client, &registry, &image, &tag, &token);

    // Step 3: Extract layer digests
    let layers = get_layers(&manifest);
    println!("Found {} layers", layers.len());

    // Step 4: Create output directory
    fs::create_dir_all(output_dir).expect("failed to create output dir");

    // Step 5: Download and extract each layer
    for (i, digest) in layers.iter().enumerate() {
        println!(
            "[{}/{}] Downloading layer {}...",
            i + 1,
            layers.len(),
            &digest[..19]
        );
        download_and_extract_layer(&client, &registry, &image, digest, &token, output_dir);
    }

    // Step 6: Strip quarantine xattrs (macOS)
    println!("Stripping quarantine xattrs...");
    let _ = Command::new("xattr")
        .args(["-cr", output_dir])
        .status();

    println!("Done! Rootfs extracted to {output_dir}");
}

/// Registry info for API endpoint construction.
struct RegistryInfo {
    /// Base URL for the v2 API (e.g. "https://registry-1.docker.io")
    api_base: String,
    /// Auth token URL template. {image} and {scope} are substituted.
    auth_url: String,
}

fn registry_info(registry: &str) -> RegistryInfo {
    match registry {
        "docker.io" => RegistryInfo {
            api_base: "https://registry-1.docker.io".into(),
            auth_url: "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull".into(),
        },
        "ghcr.io" => RegistryInfo {
            api_base: "https://ghcr.io".into(),
            auth_url: "https://ghcr.io/token?scope=repository:{image}:pull".into(),
        },
        other => {
            // Generic OCI registry — try token endpoint at the registry itself
            let base = format!("https://{other}");
            RegistryInfo {
                api_base: base.clone(),
                auth_url: format!("{base}/token?scope=repository:{{image}}:pull"),
            }
        }
    }
}

/// Parse image reference into (registry, image, tag).
/// Examples:
///   "python:3.12-alpine"            -> ("docker.io", "library/python", "3.12-alpine")
///   "myuser/myrepo:v1"              -> ("docker.io", "myuser/myrepo", "v1")
///   "ghcr.io/owner/repo:latest"     -> ("ghcr.io", "owner/repo", "latest")
///   "quay.io/org/repo"              -> ("quay.io", "org/repo", "latest")
fn parse_image_ref(reference: &str) -> (String, String, String) {
    let (name, tag) = if let Some((n, t)) = reference.split_once(':') {
        (n.to_string(), t.to_string())
    } else {
        (reference.to_string(), "latest".to_string())
    };

    // Check if the first component looks like a registry hostname
    // (contains a dot or is "localhost")
    let parts: Vec<&str> = name.splitn(2, '/').collect();
    if parts.len() == 2 && (parts[0].contains('.') || parts[0] == "localhost") {
        let registry = parts[0].to_string();
        let image = parts[1].to_string();
        return (registry, image, tag);
    }

    // Docker Hub: add "library/" prefix for official images (no slash)
    let image = if !name.contains('/') {
        format!("library/{name}")
    } else {
        name
    };

    ("docker.io".into(), image, tag)
}

fn get_auth_token(client: &Client, registry: &str, image: &str) -> String {
    let info = registry_info(registry);
    let url = info.auth_url.replace("{image}", image);
    let resp: Value = client.get(&url).send().unwrap().json().unwrap();
    resp["token"].as_str().expect("no token in auth response").to_string()
}

fn get_manifest(client: &Client, registry: &str, image: &str, tag: &str, token: &str) -> Value {
    let info = registry_info(registry);
    let url = format!("{}/v2/{image}/manifests/{tag}", info.api_base);
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.list.v2+json, \
             application/vnd.oci.image.index.v1+json",
        )
        .send()
        .unwrap()
        .text()
        .unwrap();

    let manifest: Value = serde_json::from_str(&resp).expect("invalid manifest JSON");

    // Check if this is a fat manifest (manifest list / OCI index)
    let media_type = manifest["mediaType"].as_str().unwrap_or("");
    let schema_version = manifest["schemaVersion"].as_u64().unwrap_or(0);

    if media_type.contains("manifest.list") || media_type.contains("image.index")
        || (schema_version == 2 && manifest.get("manifests").is_some())
    {
        println!("Fat manifest detected, selecting linux/arm64...");
        return resolve_platform_manifest(client, registry, image, token, &manifest, "arm64");
    }

    manifest
}

fn resolve_platform_manifest(
    client: &Client,
    registry: &str,
    image: &str,
    token: &str,
    index: &Value,
    arch: &str,
) -> Value {
    let manifests = index["manifests"].as_array().expect("no manifests array in index");

    let entry = manifests
        .iter()
        .find(|m| {
            let platform = &m["platform"];
            platform["architecture"].as_str() == Some(arch)
                && platform["os"].as_str() == Some("linux")
        })
        .unwrap_or_else(|| {
            for m in manifests {
                let p = &m["platform"];
                eprintln!(
                    "  available: {}/{}",
                    p["os"].as_str().unwrap_or("?"),
                    p["architecture"].as_str().unwrap_or("?")
                );
            }
            panic!("no linux/{arch} manifest found");
        });

    let digest = entry["digest"].as_str().expect("no digest in manifest entry");
    let media_type = entry["mediaType"].as_str().unwrap_or(
        "application/vnd.docker.distribution.manifest.v2+json"
    );

    println!("  -> resolving {digest}");

    let info = registry_info(registry);
    let url = format!("{}/v2/{image}/manifests/{digest}", info.api_base);
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", media_type)
        .send()
        .unwrap()
        .text()
        .unwrap();

    serde_json::from_str(&resp).expect("invalid platform manifest JSON")
}

fn get_layers(manifest: &Value) -> Vec<String> {
    manifest["layers"]
        .as_array()
        .expect("no layers in manifest")
        .iter()
        .map(|layer| {
            layer["digest"]
                .as_str()
                .expect("no digest in layer")
                .to_string()
        })
        .collect()
}

fn download_and_extract_layer(
    client: &Client,
    registry: &str,
    image: &str,
    digest: &str,
    token: &str,
    output_dir: &str,
) {
    let info = registry_info(registry);
    let url = format!("{}/v2/{image}/blobs/{digest}", info.api_base);
    let mut resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .expect("failed to download layer");

    if !resp.status().is_success() {
        panic!(
            "failed to download layer {}: HTTP {}",
            digest,
            resp.status()
        );
    }

    // Read the whole blob into memory (layers are typically <100MB)
    let mut blob = Vec::new();
    resp.read_to_end(&mut blob).expect("failed to read layer blob");
    let size_mb = blob.len() as f64 / (1024.0 * 1024.0);
    println!("  downloaded {size_mb:.1} MB, extracting...");

    // Decompress gzip and extract tar
    let decoder = flate2::read::GzDecoder::new(&blob[..]);
    let mut archive = tar::Archive::new(decoder);

    let output = Path::new(output_dir);

    for entry in archive.entries().expect("failed to read tar entries") {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  warning: skipping bad tar entry: {e}");
                continue;
            }
        };

        let path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(e) => {
                eprintln!("  warning: skipping entry with bad path: {e}");
                continue;
            }
        };

        // Skip dangerous paths that hang macOS
        let path_str = path.to_string_lossy();
        if path_str.starts_with("dev/")
            || path_str == "dev"
            || path_str.starts_with("proc/")
            || path_str == "proc"
            || path_str.starts_with("sys/")
            || path_str == "sys"
            || path_str.starts_with("./dev/")
            || path_str == "./dev"
            || path_str.starts_with("./proc/")
            || path_str == "./proc"
            || path_str.starts_with("./sys/")
            || path_str == "./sys"
        {
            continue;
        }

        // Skip device nodes, fifos, etc — only extract regular files, dirs, symlinks
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link()) {
            continue;
        }

        // Unpack into output directory
        if let Err(e) = entry.unpack_in(output) {
            eprintln!("  warning: failed to unpack {}: {e}", path_str);
        }
    }
}
