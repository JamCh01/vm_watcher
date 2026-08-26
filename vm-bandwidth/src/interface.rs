//! TAP discovery under the configured bridge.
//!
//! Interface names are never used for identification: the host uses purely numeric TAP
//! names (e.g. `5301708445`). A port of `br0` is a TAP iff it exposes
//! `/sys/class/net/<if>/tun_flags` (only tun/tap devices do) with the IFF_TAP type bit.

use std::fs;

#[derive(Debug, Clone)]
pub struct Tap {
    pub name: String,
    pub ifindex: u32,
}

/// List the TAP interfaces enslaved to `bridge`. Returns an error only if the bridge's
/// `brif` directory cannot be read; interfaces that disappear mid-scan are skipped.
pub fn discover_taps(bridge: &str) -> Result<Vec<Tap>, String> {
    let brif = format!("/sys/class/net/{bridge}/brif");
    let entries = fs::read_dir(&brif).map_err(|e| format!("cannot read {brif}: {e}"))?;

    let mut taps = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(ifindex) = read_ifindex(&name) else {
            continue;
        };
        if is_tap(&name) {
            taps.push(Tap { name, ifindex });
        }
    }
    taps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(taps)
}

fn read_ifindex(name: &str) -> Option<u32> {
    fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

// IFF_TUN = 0x0001, IFF_TAP = 0x0002; the device type lives in the low nibble.
const IFF_TYPE_MASK: u32 = 0x000f;
const IFF_TAP: u32 = 0x0002;

fn is_tap(name: &str) -> bool {
    let Ok(raw) = fs::read_to_string(format!("/sys/class/net/{name}/tun_flags")) else {
        return false;
    };
    let raw = raw.trim().trim_start_matches("0x");
    let Ok(flags) = u32::from_str_radix(raw, 16) else {
        return false;
    };
    flags & IFF_TYPE_MASK == IFF_TAP
}
