use crate::hasher::IterHasher;
use core::marker::PhantomData;

/// An `n`-to-1 compression function, like `CompressionFunction`, except that TODO.
pub trait PseudoCompressionFunction<T, const N: usize> {
    fn compress(&self, input: [T; N]) -> T;
}

/// An `n`-to-1 compression function.
pub trait CompressionFunction<T, const N: usize>: PseudoCompressionFunction<T, N> {}

pub struct CompressionFunctionFromIterHasher<T, H, const N: usize, const CHUNK: usize>
where
    H: IterHasher<T, [T; CHUNK]>,
{
    _phantom_t: PhantomData<T>,
    hasher: H,
}

impl<T, H, const N: usize, const CHUNK: usize> PseudoCompressionFunction<[T; CHUNK], N>
    for CompressionFunctionFromIterHasher<T, H, N, CHUNK>
where
    H: IterHasher<T, [T; CHUNK]>,
{
    fn compress(&self, input: [[T; CHUNK]; N]) -> [T; CHUNK] {
        self.hasher.hash_iter(input.into_iter().flatten())
    }
}

impl<T, H, const N: usize, const CHUNK: usize> CompressionFunction<[T; CHUNK], N>
    for CompressionFunctionFromIterHasher<T, H, N, CHUNK>
where
    H: IterHasher<T, [T; CHUNK]>,
{
}
