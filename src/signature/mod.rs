
use std::result;

use rand::{rngs::OsRng, Rng};
enum Index {
    Zero = 0,
    One = 1,
}

struct PrivateKey{
  index:Index,
  data:[String;8]

}

impl PrivateKey{
    fn index_zero()->Self{
 
        let mut rng=OsRng;
        let data:[u32;8]=rng.gen();
        let mut hex_data: [String; 8] = Default::default(); 

     
        for (i, &num) in data.iter().enumerate() {
            hex_data[i] = format!("{:08X}", num);
        }

        PrivateKey{
            index:Index::Zero,
            data:hex_data
        }

    }
    fn index_one()->Self{
        let mut rng=OsRng;
        let data:[u32;8]=rng.gen();
        let mut hex_data: [String; 8] = Default::default(); 

     
        for (i, &num) in data.iter().enumerate() {
            hex_data[i] = format!("{:08X}", num);
        }

        PrivateKey{
            index:Index::One,
            data:hex_data
        }

    }
}

fn generate_keys()->String{
let private_key:String={
let mut result=String::new();

 for element in PrivateKey::index_zero().data.iter(){
result.push_str(&element.to_string());
 }
  for element in PrivateKey::index_one().data.iter(){
result.push_str(&element.to_string());
 }

result
    };
    private_key

}


#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn secret_key_is_512_bits(){
       let private_key: String=generate_keys();
   
      assert_eq!(private_key.len()*4, 512, "Private key is not 512 bits long");
      
    }
}

// fn sign(secret_key:&str, message:&str)->String{

// }
// fn verify(public_key:&str, message:&str, signature:&str)->bool{

// }
// fn generate_private_key(){

// }