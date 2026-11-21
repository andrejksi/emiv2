#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub fn range_u64(&mut self, bound: u64) -> u64 {
        assert!(bound > 0);
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u64();
            if r >= threshold {
                return r % bound;
            }
        }
    }

    pub fn range_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0);
        self.range_u64(bound as u64) as usize
    }

    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        assert!(den > 0 && num <= den);
        self.range_u64(den) < num
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        assert!(!items.is_empty());
        &items[self.range_usize(items.len())]
    }

    pub fn next_i64_range(&mut self, lo: i64, hi: i64) -> i64 {
        assert!(lo <= hi);
        let span = (hi as i128 - lo as i128 + 1) as u64;
        (lo as i128 + self.range_u64(span) as i128) as i64
    }
}
