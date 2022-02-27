use rand::Rng;


pub fn mutate<T>(rand: &mut T, data: &mut Vec<u8>)
where 
  T: Rng,
{
    let num_bytes = rand.next_u64() as usize % (data.len() + 1);
    for _ in 0..num_bytes {
        let rand_idx = rand.next_u32() as usize % data.len();
        data[rand_idx] = rand::thread_rng().gen::<u8>();
    }
}
