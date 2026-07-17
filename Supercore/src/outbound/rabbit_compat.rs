use anyhow::{anyhow, Result};

const COUNTER_CONSTANTS: [u32; 8] = [
    0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3,
];

pub(super) struct RabbitCompat {
    x: [u32; 8],
    c: [u32; 8],
    carry: u32,
    block: [u8; 16],
    offset: usize,
}

impl RabbitCompat {
    pub(super) fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        let key: [u8; 16] = key
            .try_into()
            .map_err(|_| anyhow!("rabbit128-poly1305 key must be 16 bytes"))?;
        let nonce: [u8; 8] = nonce
            .try_into()
            .map_err(|_| anyhow!("rabbit128-poly1305 nonce must be 8 bytes"))?;
        let mut words = [0u16; 8];
        for (word, bytes) in words.iter_mut().zip(key.chunks_exact(2)) {
            *word = u16::from_le_bytes([bytes[0], bytes[1]]);
        }

        let mut state = Self {
            x: [0; 8],
            c: [0; 8],
            carry: 0,
            block: [0; 16],
            offset: 16,
        };
        for index in 0..8 {
            if index % 2 == 0 {
                state.x[index] = ((words[(index + 1) % 8] as u32) << 16) | words[index] as u32;
                state.c[index] =
                    ((words[(index + 4) % 8] as u32) << 16) | words[(index + 5) % 8] as u32;
            } else {
                state.x[index] =
                    ((words[(index + 5) % 8] as u32) << 16) | words[(index + 4) % 8] as u32;
                state.c[index] = ((words[index] as u32) << 16) | words[(index + 1) % 8] as u32;
            }
        }
        for _ in 0..4 {
            state.next_state();
        }
        for index in 0..8 {
            state.c[index] ^= state.x[(index + 4) % 8];
        }
        state.setup_nonce(nonce);
        Ok(state)
    }

    pub(super) fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == self.block.len() {
                self.next_state();
                self.block = self.extract();
                self.offset = 0;
            }
            *byte ^= self.block[self.offset];
            self.offset += 1;
        }
    }

    fn setup_nonce(&mut self, nonce: [u8; 8]) {
        let first = u32::from_le_bytes(nonce[..4].try_into().expect("fixed nonce half"));
        let third = u32::from_le_bytes(nonce[4..].try_into().expect("fixed nonce half"));
        let second = (first >> 16) | (third & 0xffff0000);
        let fourth = (third << 16) | (first & 0x0000ffff);
        let values = [first, second, third, fourth];
        for index in 0..8 {
            self.c[index] ^= values[index % 4];
        }
        for _ in 0..4 {
            self.next_state();
        }
    }

    fn next_state(&mut self) {
        for (index, constant) in COUNTER_CONSTANTS.iter().copied().enumerate() {
            // The deployed Rabbit-Poly1305 method stores the subtraction result
            // as carry and the borrow bit as the counter word.
            let previous = self.c[index];
            let difference = constant.wrapping_sub(previous).wrapping_sub(self.carry);
            let borrow = ((!constant & previous) | (!(constant ^ previous) & difference)) >> 31;
            self.carry = difference;
            self.c[index] = borrow;
        }

        let mut g = [0u32; 8];
        for (index, value) in g.iter_mut().enumerate() {
            let sum = self.x[index].wrapping_add(self.c[index]) as u64;
            let square = sum.wrapping_mul(sum);
            *value = (square as u32) ^ (square >> 32) as u32;
        }
        self.x[0] = g[0]
            .wrapping_add(g[7].rotate_left(16))
            .wrapping_add(g[6].rotate_left(16));
        self.x[1] = g[1].wrapping_add(g[0].rotate_left(8)).wrapping_add(g[7]);
        self.x[2] = g[2]
            .wrapping_add(g[1].rotate_left(16))
            .wrapping_add(g[0].rotate_left(16));
        self.x[3] = g[3].wrapping_add(g[2].rotate_left(8)).wrapping_add(g[1]);
        self.x[4] = g[4]
            .wrapping_add(g[3].rotate_left(16))
            .wrapping_add(g[2].rotate_left(16));
        self.x[5] = g[5].wrapping_add(g[4].rotate_left(8)).wrapping_add(g[3]);
        self.x[6] = g[6]
            .wrapping_add(g[5].rotate_left(16))
            .wrapping_add(g[4].rotate_left(16));
        self.x[7] = g[7].wrapping_add(g[6].rotate_left(8)).wrapping_add(g[5]);
    }

    fn extract(&self) -> [u8; 16] {
        let words = [
            self.x[0] ^ ((self.x[5] >> 16) | (self.x[3] << 16)),
            self.x[2] ^ ((self.x[7] >> 16) | (self.x[5] << 16)),
            self.x[4] ^ ((self.x[1] >> 16) | (self.x[7] << 16)),
            self.x[6] ^ ((self.x[3] >> 16) | (self.x[1] << 16)),
        ];
        let mut output = [0u8; 16];
        for (bytes, word) in output.chunks_exact_mut(4).zip(words) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        output
    }
}
