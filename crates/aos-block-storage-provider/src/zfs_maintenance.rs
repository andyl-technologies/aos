//! OpenZFS pool health and memory-pressure telemetry.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};

/// Runs one bounded maintenance operation.
///
/// # Errors
///
/// Returns an error when the operation is malformed, an observed pool is not
/// healthy, a required kernel counter is unavailable, or a snapshot cannot be
/// published atomically.
pub fn run(arguments: &[String]) -> Result<()> {
    match arguments {
        [operation, pool] if operation == "health" => check_health(pool),
        [operation, pool, destination] if operation == "metrics" => {
            publish_metrics(pool, Path::new(destination))
        }
        _ => bail!("expected `health POOL` or `metrics POOL DESTINATION`"),
    }
}

fn check_health(pool: &str) -> Result<()> {
    let health = zpool_output(&["list", "-H", "-o", "health", pool])?;
    ensure!(
        health.trim() == "ONLINE",
        "pool {pool} is {}",
        health.trim()
    );

    let status = zpool_output(&["status", "-p", pool])?;
    let errors = accumulated_device_errors(&status)?;
    ensure!(
        errors == 0,
        "pool {pool} has {errors} accumulated device errors"
    );

    let compatibility = zpool_output(&["get", "-H", "-o", "value", "compatibility", pool])?;
    ensure!(
        !matches!(compatibility.trim(), "" | "-" | "off"),
        "pool {pool} has no pinned compatibility feature set"
    );
    Ok(())
}

fn publish_metrics(pool: &str, destination: &Path) -> Result<()> {
    let arcstats = fs::read_to_string("/proc/spl/kstat/zfs/arcstats")
        .context("reading OpenZFS ARC statistics")?;
    let buddyinfo =
        fs::read_to_string("/proc/buddyinfo").context("reading buddy allocator state")?;
    let vmstat = fs::read_to_string("/proc/vmstat").context("reading virtual-memory counters")?;
    let health = zpool_output(&["list", "-H", "-o", "health", pool])?;
    let fragmentation = zpool_output(&["list", "-H", "-o", "fragmentation", pool])?;

    let mut metrics = String::new();
    write_arc_metrics(&mut metrics, &arcstats)?;
    write_buddy_metrics(&mut metrics, &buddyinfo)?;
    write_numa_metrics(&mut metrics)?;
    write_vm_metrics(&mut metrics, &vmstat)?;
    write_pool_metrics(&mut metrics, pool, health.trim(), fragmentation.trim())?;

    let parent = destination
        .parent()
        .context("metrics destination has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let staging = destination.with_extension("tmp");
    fs::write(&staging, metrics).with_context(|| format!("writing {}", staging.display()))?;
    fs::rename(&staging, destination)
        .with_context(|| format!("publishing {}", destination.display()))
}

fn zpool_output(arguments: &[&str]) -> Result<String> {
    let output = Command::new("zpool")
        .args(arguments)
        .output()
        .context("executing zpool")?;
    ensure!(
        output.status.success(),
        "zpool {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).context("decoding zpool output")
}

fn accumulated_device_errors(status: &str) -> Result<u64> {
    status.lines().try_fold(0_u64, |total, line| {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 5
            || !matches!(
                columns[1],
                "ONLINE" | "DEGRADED" | "FAULTED" | "OFFLINE" | "UNAVAIL" | "REMOVED"
            )
        {
            return Ok(total);
        }
        columns[2..5].iter().try_fold(total, |sum, value| {
            let count = value
                .parse::<u64>()
                .context("parsing ZFS device error count")?;
            sum.checked_add(count)
                .context("summing ZFS device error counts")
        })
    })
}

fn counter(stats: &str, name: &str) -> Result<u64> {
    stats
        .lines()
        .find_map(|line| {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            (columns.first() == Some(&name) && columns.len() >= 3).then_some(columns[2])
        })
        .context("locating kernel counter")?
        .parse::<u64>()
        .context("parsing kernel counter")
}

fn write_arc_metrics(output: &mut String, stats: &str) -> Result<()> {
    let size = counter(stats, "size")?;
    let target = counter(stats, "c")?;
    let metadata = counter(stats, "mru_metadata")? + counter(stats, "mfu_metadata")?;
    let evictable =
        counter(stats, "mru_evictable_metadata")? + counter(stats, "mfu_evictable_metadata")?;
    let pinned = metadata.saturating_sub(evictable);
    let evict_skip = counter(stats, "evict_skip")?;

    writeln!(
        output,
        "# HELP aos_zfs_arc_bytes Current ARC size in bytes."
    )?;
    writeln!(output, "# TYPE aos_zfs_arc_bytes gauge")?;
    writeln!(output, "aos_zfs_arc_bytes {size}")?;
    writeln!(
        output,
        "# HELP aos_zfs_arc_target_bytes ARC target size in bytes."
    )?;
    writeln!(output, "# TYPE aos_zfs_arc_target_bytes gauge")?;
    writeln!(output, "aos_zfs_arc_target_bytes {target}")?;
    writeln!(
        output,
        "# HELP aos_zfs_arc_metadata_bytes ARC metadata by evictability."
    )?;
    writeln!(output, "# TYPE aos_zfs_arc_metadata_bytes gauge")?;
    writeln!(
        output,
        "aos_zfs_arc_metadata_bytes{{state=\"evictable\"}} {evictable}"
    )?;
    writeln!(
        output,
        "aos_zfs_arc_metadata_bytes{{state=\"pinned\"}} {pinned}"
    )?;
    writeln!(
        output,
        "# HELP aos_zfs_arc_evict_skip_total Eviction candidates skipped."
    )?;
    writeln!(output, "# TYPE aos_zfs_arc_evict_skip_total counter")?;
    writeln!(output, "aos_zfs_arc_evict_skip_total {evict_skip}")?;
    Ok(())
}

fn write_buddy_metrics(output: &mut String, buddyinfo: &str) -> Result<()> {
    writeln!(
        output,
        "# HELP aos_memory_free_blocks Free buddy-allocator blocks by order and NUMA node."
    )?;
    writeln!(output, "# TYPE aos_memory_free_blocks gauge")?;
    for line in buddyinfo.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 5 || columns[0] != "Node" {
            continue;
        }
        let node = columns[1].trim_end_matches(',');
        let zone = columns[3];
        for (order, count) in columns[4..].iter().enumerate() {
            ensure!(
                count.parse::<u64>().is_ok(),
                "invalid buddy allocator count"
            );
            writeln!(
                output,
                "aos_memory_free_blocks{{node=\"{node}\",zone=\"{zone}\",order=\"{order}\"}} {count}"
            )?;
        }
    }
    Ok(())
}

fn write_numa_metrics(output: &mut String) -> Result<()> {
    writeln!(
        output,
        "# HELP aos_memory_node_bytes Per-NUMA-node memory by state."
    )?;
    writeln!(output, "# TYPE aos_memory_node_bytes gauge")?;
    let nodes = Path::new("/sys/devices/system/node");
    for entry in fs::read_dir(nodes).with_context(|| format!("reading {}", nodes.display()))? {
        let entry = entry.context("reading NUMA node entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(node) = name.strip_prefix("node") else {
            continue;
        };
        let path = entry.path().join("meminfo");
        if !path.is_file() {
            continue;
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        for line in contents.lines() {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            if columns.len() < 4 {
                continue;
            }
            let state = match columns[2] {
                "MemFree:" => "free",
                "SUnreclaim:" => "unreclaimable_slab",
                _ => continue,
            };
            let kilobytes = columns[3]
                .parse::<u64>()
                .context("parsing NUMA memory counter")?;
            let bytes = kilobytes
                .checked_mul(1024)
                .context("converting NUMA memory counter")?;
            writeln!(
                output,
                "aos_memory_node_bytes{{node=\"{node}\",state=\"{state}\"}} {bytes}"
            )?;
        }
    }
    Ok(())
}

fn write_vm_metrics(output: &mut String, vmstat: &str) -> Result<()> {
    writeln!(
        output,
        "# HELP aos_memory_compaction_total Kernel compaction attempts by outcome."
    )?;
    writeln!(output, "# TYPE aos_memory_compaction_total counter")?;
    for (name, outcome) in [
        ("compact_stall", "stall"),
        ("compact_fail", "fail"),
        ("compact_success", "success"),
    ] {
        let prefix = format!("{name} ");
        let value = vmstat
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .context("locating compaction counter")?;
        ensure!(value.parse::<u64>().is_ok(), "invalid compaction counter");
        writeln!(
            output,
            "aos_memory_compaction_total{{outcome=\"{outcome}\"}} {value}"
        )?;
    }
    Ok(())
}

fn write_pool_metrics(
    output: &mut String,
    pool: &str,
    health: &str,
    fragmentation: &str,
) -> Result<()> {
    ensure!(
        pool.chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.:-".contains(character)),
        "invalid pool metric label"
    );
    ensure!(
        health
            .chars()
            .all(|character| character.is_ascii_uppercase()),
        "invalid health metric label"
    );
    let online = u8::from(health == "ONLINE");
    writeln!(
        output,
        "# HELP aos_zfs_pool_health Pool health, 1 when online."
    )?;
    writeln!(output, "# TYPE aos_zfs_pool_health gauge")?;
    writeln!(
        output,
        "aos_zfs_pool_health{{pool=\"{pool}\",state=\"{health}\"}} {online}"
    )?;

    if let Some(percent) = fragmentation.strip_suffix('%') {
        let percent = percent
            .parse::<u64>()
            .context("parsing pool fragmentation")?;
        ensure!(percent <= 100, "pool fragmentation exceeds 100 percent");
        writeln!(
            output,
            "# HELP aos_zfs_pool_fragmentation_ratio Free-space fragmentation, 0 to 1."
        )?;
        writeln!(output, "# TYPE aos_zfs_pool_fragmentation_ratio gauge")?;
        writeln!(
            output,
            "aos_zfs_pool_fragmentation_ratio{{pool=\"{pool}\"}} {:.2}",
            percent as f64 / 100.0
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_device_rows() {
        let status = "NAME STATE READ WRITE CKSUM\npool ONLINE 0 0 0\n  disk ONLINE 2 3 4\nerrors: No known data errors\n";
        assert_eq!(accumulated_device_errors(status).unwrap(), 9);
    }

    #[test]
    fn emits_arc_pressure_evidence() {
        let stats = "size 4 100\nc 4 80\nmru_metadata 4 30\nmru_evictable_metadata 4 10\nmfu_metadata 4 20\nmfu_evictable_metadata 4 5\nevict_skip 4 7\n";
        let mut output = String::new();
        write_arc_metrics(&mut output, stats).unwrap();
        assert!(output.contains("aos_zfs_arc_bytes 100"));
        assert!(output.contains("state=\"pinned\"} 35"));
        assert!(output.contains("aos_zfs_arc_evict_skip_total 7"));
    }

    #[test]
    fn emits_pool_health_and_fragmentation() {
        let mut output = String::new();
        write_pool_metrics(&mut output, "tank", "ONLINE", "37%").unwrap();
        assert!(output.contains("aos_zfs_pool_health{pool=\"tank\",state=\"ONLINE\"} 1"));
        assert!(output.contains("aos_zfs_pool_fragmentation_ratio{pool=\"tank\"} 0.37"));
    }
}
