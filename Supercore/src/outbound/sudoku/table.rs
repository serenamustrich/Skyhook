use std::collections::HashMap;

use anyhow::{anyhow, bail};
use sha2::{Digest, Sha256};

use super::go_rand::GoRand;

#[derive(Clone)]
pub(super) struct SudokuTable {
    pub(super) encode: Vec<Vec<[u8; 4]>>,
    pub(super) decode: HashMap<u32, u8>,
    pub(super) padding: Vec<u8>,
    pub(super) hint: u32,
    layout: Layout,
}

#[derive(Clone)]
struct Layout {
    hint: [bool; 256],
    encoded: [[u8; 16]; 4],
    packed_decoded: [u8; 256],
    packed_valid: [bool; 256],
    pad_marker: u8,
    padding: Vec<u8>,
}

impl Layout {
    fn hint_byte(&self, value: u8, position: u8) -> u8 {
        self.encoded[value as usize][position as usize]
    }

    fn decode_hint(&self, byte: u8) -> bool {
        self.hint[byte as usize]
    }

    fn decode_packed_group(&self, byte: u8) -> Option<u8> {
        self.packed_valid[byte as usize].then_some(self.packed_decoded[byte as usize])
    }
}

#[derive(Clone, Copy)]
struct Grid([u8; 16]);

impl SudokuTable {
    pub(super) fn pair(
        key: &str,
        table_type: &str,
        custom_table: Option<&str>,
    ) -> anyhow::Result<(Self, Self)> {
        let (uplink, downlink) = parse_table_type(table_type)?;
        let up_pattern = if uplink == "entropy" { custom_table } else { None };
        let down_pattern = if downlink == "entropy" { custom_table } else { None };
        let hint = table_hint(key, table_type, up_pattern, down_pattern);
        let up = Self::build(key, &uplink, up_pattern, hint)?;
        if uplink == downlink && up_pattern == down_pattern {
            return Ok((up.clone(), up));
        }
        let down = Self::build(key, &downlink, down_pattern, hint)?;
        Ok((up, down))
    }

    fn build(key: &str, preference: &str, custom: Option<&str>, hint: u32) -> anyhow::Result<Self> {
        let layout = Layout::new(preference, custom)?;
        let grids = all_grids();
        anyhow::ensure!(grids.len() == 288, "unexpected 4x4 sudoku grid count: {}", grids.len());

        let digest = Sha256::digest(key.as_bytes());
        let seed = u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix"));
        let mut shuffled = grids.clone();
        let mut rng = GoRand::new(seed as i64);
        for index in (1..shuffled.len()).rev() {
            let other = rng.intn(index + 1);
            shuffled.swap(index, other);
        }

        let positions = hint_positions();
        let mut uniqueness: HashMap<u64, u16> = HashMap::with_capacity(positions.len() * grids.len());
        for (position_index, position) in positions.iter().enumerate() {
            for (grid_index, grid) in grids.iter().enumerate() {
                let code = values_code(grid, position);
                let key = ((position_index as u64) << 8) | code as u64;
                uniqueness
                    .entry(key)
                    .and_modify(|value| *value = u16::MAX)
                    .or_insert(grid_index as u16);
            }
        }

        let mut encode = vec![Vec::new(); 256];
        let mut decode = HashMap::with_capacity(256 * 8);
        for (byte, grid) in shuffled.iter().take(256).enumerate() {
            for (position_index, position) in positions.iter().enumerate() {
                let key = ((position_index as u64) << 8) | values_code(grid, position) as u64;
                if uniqueness.get(&key) != Some(&(grids.iter().position(|candidate| candidate.0 == grid.0).unwrap() as u16)) {
                    continue;
                }
                let mut hints = [0u8; 4];
                for (slot, position) in position.iter().enumerate() {
                    hints[slot] = layout.hint_byte(grid.0[*position as usize] - 1, *position);
                }
                let mut sorted = hints;
                sorted.sort_unstable();
                decode.insert(pack(sorted), byte as u8);
                encode[byte].push(hints);
            }
            if encode[byte].is_empty() {
                bail!("sudoku table has no unique encoding for byte {byte}");
            }
        }

        Ok(Self {
            encode,
            decode,
            padding: layout.padding.clone(),
            hint,
            layout,
        })
    }

    pub(super) fn is_hint(&self, byte: u8) -> bool {
        self.layout.decode_hint(byte)
    }

    pub(super) fn is_packed_group(&self, byte: u8) -> Option<u8> {
        self.layout.decode_packed_group(byte)
    }

    #[cfg(test)]
    pub(super) fn packed_encode(&self, group: u8) -> u8 {
        let group = group & 0x3f;
        match self.layout.pad_marker {
            0x3f => if group == 0x3f { b'\n' } else { 0x40 | group },
            0x80 => ((group & 0x30) << 1) | (group & 0x0f),
            _ => {
                // Custom layouts are already represented by the inverse map. Find the
                // canonical byte without duplicating the layout parser here.
                (0..=u8::MAX)
                    .find(|byte| self.layout.decode_packed_group(*byte) == Some(group))
                    .unwrap_or_default()
            }
        }
    }

    pub(super) fn packed_pad_marker(&self) -> u8 {
        self.layout.pad_marker
    }

}

impl Layout {
    fn new(preference: &str, custom: Option<&str>) -> anyhow::Result<Self> {
        let preference = match preference.trim().to_ascii_lowercase().as_str() {
            "ascii" | "prefer_ascii" => "ascii",
            "" | "entropy" | "prefer_entropy" => "entropy",
            other => bail!("unsupported sudoku table type {other}"),
        };
        if preference == "ascii" {
            let mut encoded = [[0u8; 16]; 4];
            let mut hint = [false; 256];
            for value in 0..4u8 {
                for position in 0..16u8 {
                    let mut byte = 0x40 | (value << 4) | position;
                    if byte == 0x7f {
                        byte = b'\n';
                    }
                    encoded[value as usize][position as usize] = byte;
                    hint[byte as usize] = true;
                }
            }
            let padding = (0x20..0x40).collect();
            let mut packed_decoded = [0u8; 256];
            let mut packed_valid = [false; 256];
            for byte in 0..=u8::MAX {
                if byte & 0x40 == 0x40 || byte == b'\n' {
                    packed_valid[byte as usize] = true;
                    packed_decoded[byte as usize] = if byte == b'\n' { 0x3f } else { byte & 0x3f };
                }
            }
            return Ok(Self { hint, encoded, packed_decoded, packed_valid, pad_marker: 0x3f, padding });
        }
        if let Some(pattern) = custom.filter(|value| !value.trim().is_empty()) {
            return Self::custom(pattern);
        }
        let mut encoded = [[0u8; 16]; 4];
        let mut hint = [false; 256];
        for value in 0..4u8 {
            for position in 0..16u8 {
                let byte = (value << 5) | position;
                encoded[value as usize][position as usize] = byte;
                if byte & 0x90 == 0 {
                    hint[byte as usize] = true;
                }
            }
        }
        let mut padding = Vec::with_capacity(16);
        for index in 0..8u8 {
            padding.push(0x80 | index);
            padding.push(0x10 | index);
        }
        let mut packed_decoded = [0u8; 256];
        let mut packed_valid = [false; 256];
        for byte in 0..=u8::MAX {
            if byte & 0x90 == 0 {
                packed_valid[byte as usize] = true;
                packed_decoded[byte as usize] = ((byte >> 1) & 0x30) | (byte & 0x0f);
            }
        }
        Ok(Self { hint, encoded, packed_decoded, packed_valid, pad_marker: 0x80, padding })
    }

    fn custom(pattern: &str) -> anyhow::Result<Self> {
        let clean = pattern.trim().replace(' ', "").to_ascii_lowercase();
        if clean.len() != 8 || clean.chars().filter(|c| *c == 'x').count() != 2
            || clean.chars().filter(|c| *c == 'p').count() != 2
            || clean.chars().filter(|c| *c == 'v').count() != 4
        {
            bail!("custom sudoku table must contain 8 symbols: 2 x, 2 p, 4 v");
        }
        let mut x_bits = Vec::new();
        let mut p_bits = Vec::new();
        let mut v_bits = Vec::new();
        for (index, symbol) in clean.bytes().enumerate() {
            let bit = 7 - index as u8;
            match symbol {
                b'x' => x_bits.push(bit),
                b'p' => p_bits.push(bit),
                b'v' => v_bits.push(bit),
                _ => bail!("invalid custom sudoku table symbol"),
            }
        }
        let x_mask = x_bits.iter().fold(0u8, |mask, bit| mask | (1 << bit));
        let encode_bits = |value: u8, position: u8| {
            let mut output = x_mask;
            if value & 2 != 0 { output |= 1 << p_bits[0]; }
            if value & 1 != 0 { output |= 1 << p_bits[1]; }
            for (index, bit) in v_bits.iter().enumerate() {
                if position & (1 << (3 - index as u8)) != 0 { output |= 1 << bit; }
            }
            output
        };
        let mut encoded = [[0u8; 16]; 4];
        for value in 0..4u8 { for position in 0..16u8 { encoded[value as usize][position as usize] = encode_bits(value, position); } }
        let mut hint = [false; 256];
        for value in 0..4u8 {
            for position in 0..16u8 {
                hint[encoded[value as usize][position as usize] as usize] = true;
            }
        }
        let mut padding = Vec::new();
        for drop in x_bits {
            for value in 0..4u8 {
                for position in 0..16u8 {
                    let mut byte = encode_bits(value, position);
                    byte &= !(1 << drop);
                    if byte.count_ones() >= 5 && !padding.contains(&byte) { padding.push(byte); }
                }
            }
        }
        padding.sort_unstable();
        anyhow::ensure!(!padding.is_empty(), "custom sudoku table has no padding bytes");
        let mut packed_decoded = [0u8; 256];
        let mut packed_valid = [false; 256];
        for byte in 0..=u8::MAX {
            if (byte & x_mask) != x_mask {
                continue;
            }
            packed_valid[byte as usize] = true;
            let mut value = 0u8;
            if byte & (1 << p_bits[0]) != 0 { value |= 0x02; }
            if byte & (1 << p_bits[1]) != 0 { value |= 0x01; }
            let mut position = 0u8;
            for (index, bit) in v_bits.iter().enumerate() {
                if byte & (1 << bit) != 0 { position |= 1 << (3 - index as u8); }
            }
            packed_decoded[byte as usize] = (value << 4) | position;
        }
        let pad_marker = *padding.first().expect("custom layout padding");
        Ok(Self { hint, encoded, packed_decoded, packed_valid, pad_marker, padding })
    }
}

fn parse_table_type(value: &str) -> anyhow::Result<(String, String)> {
    let raw = value.trim().to_ascii_lowercase();
    match raw.as_str() {
        "" | "entropy" | "prefer_entropy" => Ok(("entropy".into(), "entropy".into())),
        "ascii" | "prefer_ascii" => Ok(("ascii".into(), "ascii".into())),
        _ if raw.starts_with("up_") => {
            let Some((up, down)) = raw.strip_prefix("up_").and_then(|value| value.split_once("_down_")) else {
                bail!("invalid sudoku table type {value}");
            };
            Ok((normalize_preference(up)?, normalize_preference(down)?))
        }
        _ => bail!("invalid sudoku table type {value}"),
    }
}

fn normalize_preference(value: &str) -> anyhow::Result<String> {
    match value {
        "ascii" | "prefer_ascii" => Ok("ascii".into()),
        "entropy" | "prefer_entropy" => Ok("entropy".into()),
        _ => Err(anyhow!("invalid sudoku table direction {value}")),
    }
}

fn table_hint(key: &str, mode: &str, up: Option<&str>, down: Option<&str>) -> u32 {
    let mut hash = Sha256::new();
    hash.update(b"sudoku-table-hint\0");
    hash.update(key.as_bytes());
    hash.update(b"\0");
    hash.update(mode.as_bytes());
    hash.update(b"\0");
    hash.update(up.unwrap_or("").trim().to_ascii_lowercase().as_bytes());
    hash.update(b"\0");
    hash.update(down.unwrap_or("").trim().to_ascii_lowercase().as_bytes());
    let digest = hash.finalize();
    u32::from_be_bytes(digest[..4].try_into().expect("sha256 prefix"))
}

fn all_grids() -> Vec<Grid> {
    fn fill(index: usize, grid: &mut [u8; 16], output: &mut Vec<Grid>) {
        if index == 16 {
            output.push(Grid(*grid));
            return;
        }
        let row = index / 4;
        let column = index % 4;
        let block_row = (row / 2) * 2;
        let block_column = (column / 2) * 2;
        for value in 1..=4u8 {
            if (0..4).any(|other| grid[row * 4 + other] == value)
                || (0..4).any(|other| grid[other * 4 + column] == value)
                || (0..2).any(|r| (0..2).any(|c| grid[(block_row + r) * 4 + block_column + c] == value))
            {
                continue;
            }
            grid[index] = value;
            fill(index + 1, grid, output);
            grid[index] = 0;
        }
    }
    let mut output = Vec::with_capacity(288);
    fill(0, &mut [0; 16], &mut output);
    output
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut result = Vec::with_capacity(1_820);
    for a in 0..13u8 { for b in (a + 1)..14u8 { for c in (b + 1)..15u8 { for d in (c + 1)..16u8 { result.push([a, b, c, d]); }}}}
    result
}

fn values_code(grid: &Grid, positions: &[u8; 4]) -> u8 {
    positions.iter().enumerate().fold(0u8, |code, (index, position)| {
        code | ((grid.0[*position as usize] - 1) << (index * 2))
    })
}

fn pack(mut values: [u8; 4]) -> u32 {
    values.sort_unstable();
    u32::from_be_bytes(values)
}
