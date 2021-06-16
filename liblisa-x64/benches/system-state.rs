use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use liblisa_core::{Location, arch::{Arch, MemoryState, Permissions, Register, State, SystemState, Value}};
use liblisa_x64::X64Arch;

fn create(c: &mut Criterion) {
    c.bench_function("SystemState::create", |b| b.iter(|| {
        let state = SystemState::<X64Arch> {
            cpu: State::create(|_| 0, |_| false),
            memory: MemoryState::new([ (0x0, Permissions::Execute, vec![ 0x00, 0xf0, 0x20, 0x50, 0x99, 0xab ]) ].iter().cloned())
        };

        black_box(state);
    }));
}

fn clone(c: &mut Criterion) {
    let state = SystemState::<X64Arch> {
        cpu: State::create(|_| 0, |_| false),
        memory: MemoryState::new([ (0x0, Permissions::Execute, vec![ 0x00, 0xf0, 0x20, 0x50, 0x99, 0xab ]) ].iter().cloned())
    };

    c.bench_function("SystemState::clone", |b| b.iter(|| {
        black_box(state.clone());
    }));
}

fn set_single_location(c: &mut Criterion) {
    let mut state = SystemState::<X64Arch> {
        cpu: State::create(|_| 0, |_| false),
        memory: MemoryState::new([ (0x0, Permissions::Execute, vec![ 0x00, 0xf0, 0x20, 0x50, 0x99, 0xab ]) ].iter().cloned())
    };
    
    let input_locations: Vec<Location<X64Arch>> = <X64Arch as Arch>::Reg::iter()
        .map(|reg| Location::Reg(reg))
        .collect::<Vec<_>>();
    
    c.bench_function("SystemState::set_location", |b| b.iter(|| {
        for loc in input_locations.iter() {
            state.set_location(loc, Value::Num(10));
        }

        black_box(&state);
    }));
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = create, clone, set_single_location
}
criterion_main!(benches);