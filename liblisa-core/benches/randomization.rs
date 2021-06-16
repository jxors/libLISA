use std::time::Duration;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn randomized_value(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("randomized_value", |b| b.iter(|| {
        black_box(liblisa_core::randomized_value(&mut rng));
    }));
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = randomized_value
}
criterion_main!(benches);