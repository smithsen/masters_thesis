use image::{open,imageops};
use image::{DynamicImage};
use image::EncodableLayout;
//use image::imageops::BiLevel;
use bellman::{gadgets::{boolean::{AllocatedBit, Boolean},multipack,sha256::sha256,},Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Bls12;//field used
use ff::PrimeField;
//use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
//use bitvec::prelude::*;
//use std::time::{Duration,Instant};
use std::time::{Duration,Instant};
use bellman::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof
};



const LEN : usize = 100;
const WID : usize = 100;
const SIZE: usize = LEN*WID;
//LEN: 10; WID: 10; SIZE: 100, Param_Gen: 50.06s, Proof_Gen: 3.57s, Verification: 0.03s
//LEN: 20; WID: 20; SIZE: 400, Param_Gen: 176.57s, Proof_Gen: 12.15s, Verification: 0.016s
//LEN: 51; WID: 32; SIZE: 1632, Param_Gen: 651.7s, Proof_Gen: 49.84s, Verification: 0.051s
//LEN: 100; WID: 100; SIZE: 10000, Killed... Number of gates too much

struct MyCircuit {
    /// The input to SHA-256d we are proving that we know. Set to `None` when we
    /// are verifying a proof (and do not have the witness data).
	preimage: Option<[u8;SIZE]>,	
	a: Option<[u8;SIZE]>,
	r: Option<[u8;SIZE]>,
	
}            

fn main(){	
	let mut time_param = Duration::new(0,0);
	let mut time_prove = Duration::new(0,0);
	let mut time_verify = Duration::new(0,0);
	let start = Instant::now();	
	let params = {
		let c = MyCircuit { preimage: None, a: None, r: None, };
		generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
	};	
	//report for different curves
	time_param += start.elapsed();
	let time_param_f =
        	 time_param.subsec_nanos() as f64 / 1_000_000_000f64 + (time_param.as_secs() as f64);
	
	// Prepare the verification key (for proof verification).
	let pvk = prepare_verifying_key(&params.vk);	
	
	//For the original image	
	let img = open("thesis2_redacted.jpg").unwrap();
	let gray = img.to_luma8();
	gray.save("grayscale.png").unwrap();
	let img_arr = gray.as_bytes();
	let length = img_arr.len();
	println!("{:?}", length);
	let mut dummy: [u8; SIZE] = [0;SIZE];
	for i in 0..SIZE{
		dummy[i] = img_arr[i];	
	}
	//println!("{:?}",dummy);

	
	//document
	let a: [u8; SIZE] = dummy;//document for redaction
	let preimage: [u8; SIZE] = dummy;//preimage for sha

	//for redacted image
	let img_r = open("thesis2_redacted_new.jpg").unwrap();
	let gray_r = img_r.to_luma8();
	gray_r.save("redacted_grayscale.png").unwrap();
	let img_arr_red = gray_r.as_bytes();
	let mut dummyagain: [u8;SIZE] = [0;SIZE];
	for i in 0..SIZE{
		dummyagain[i] = img_arr_red[i];	
	}
	println!("document:");
	println!("{:?}",a);	
	println!("further computation...");
	let mut redactor: [u8; SIZE] = [1;SIZE];
	println!("redacting vector:");
	println!("{:?}",redactor);
	let value: [u8; SIZE] = redact_external(&dummy, &redactor);//redacted
	println!("redacted vector:");
	println!("{:?}",value);
	let r: [u8; SIZE] = for_and(&redactor);	//redactor
	println!("rredacting vector: {:?}",r);
	
	let hash  = Sha256::digest(&preimage);
	let c = MyCircuit {
		preimage: Some(preimage), a: Some(a), r: Some(r),
	};
	let proof = create_random_proof(c, &params, &mut OsRng).unwrap();
	time_prove += start.elapsed();
	let time_prove_f =
        	 time_prove.subsec_nanos() as f64 / 1_000_000_000f64 + (time_prove.as_secs() as f64);
	// Pack the hash as inputs for proof verification.
	let mut hash_bits = multipack::bytes_to_bits_le(&hash);
	let value_bits = multipack::bytes_to_bits_le(&value);
	hash_bits.extend(value_bits.iter().cloned());//merging two inputs for verifier
	let inputs = multipack::compute_multipacking(&hash_bits);//give to verifier

	assert!(verify_proof(&pvk, &proof, &inputs).is_ok());
	let mat: Vec<_> = value
    	.chunks_exact(WID)
    	.take(LEN)
    	.map(|s| s.to_vec())
    	.collect();         
	let mut final_im_buf = DynamicImage::new_luma8(WID as u32, LEN as u32).to_luma8();
	for (y,x, pixel) in final_im_buf.enumerate_pixels_mut(){
		*pixel = image::Luma([mat[x as usize][y as usize]]);
	}
	final_im_buf.save("final_redaction.png").unwrap();
	println!("Image saved as final_redaction.png");

	time_verify += start.elapsed();
	let time_verify_f =
        	 time_verify.subsec_nanos() as f64 / 1_000_000_000f64 + (time_verify.as_secs() as f64);

	println!("Parameter generation time: {:?}",time_param_f);
	println!("Time after proof generation: {:?}",time_prove_f - time_param_f);
	println!("Time after verification: {:?}",time_verify_f - time_prove_f);		
}





//==== Internal Functions === //
// the vector that essentially hides all the crucial information
fn redaction_vector(dummyagain: &[u8], dummy: &[u8]) -> [u8;SIZE]
{
	//constructing redaction array
	let mut redaction: [u8;SIZE] = [0;SIZE];
	for i in 0..SIZE{
			if dummy[i] == dummyagain[i]{
					redaction[i] = 1;				
				}else{
					redaction[i] = 0;				
				}	
	}

	return redaction;	
}

fn redact_external(preimage: &[u8], mask: &[u8]) -> [u8; SIZE]{
	let mut internal = [0;SIZE];
	for i in 0..SIZE{
		internal[i] = preimage[i]*mask[i];
	}
return internal;
}


fn for_and(redactor: &[u8]) -> [u8; SIZE]
{
	let mut temp: [u8; SIZE] = [0; SIZE];	
	for i in 0..SIZE{
		if redactor[i] == 1 {
			temp[i] = 255;
		}else{
			temp[i] = 0;
		}
	}
	return temp;
}


//====== document redaction gadget ==== //
fn redact<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean], a: &[Boolean], r: &[Boolean]
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input_1: Vec<_> = a
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();
    let input_2: Vec<_> = r
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();
    let preimage_ip: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();
    let mut res = sha256(cs.namespace(|| "SHA-256(input)"), &preimage_ip)?;
    let mid = input_1.iter().zip(input_2)
    .map(|(x, y)| Boolean::and(&mut cs, &x, &y))
    .collect::<Result<Vec<Boolean>, SynthesisError>>()?;
    //let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;
    res.extend(mid.iter().cloned());
    // Flip endianness of each output byte
        Ok(res
    //Ok(mid
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

//==== Circuit for document redaction === //


impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
   fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
	
	
         let bit_values = if let Some(preimage) = self.preimage {
            preimage.iter().map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).flatten().map(|b| Some(b)).collect()
        } else {
            vec![None; SIZE * 8]
        };
        assert_eq!(bit_values.len(), SIZE * 8);

        // Witness the bits of the preimage.
	   // Allocate each bit.
        let preimage_bits = bit_values.into_iter().enumerate().map(|(i, b)| {AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
       })
            // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

	//=======================
	let a_values = if let Some(a) = self.a{
	a.iter().map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).flatten().map(|b| Some(b)).collect()
        } else {
            vec![None; SIZE * 8]
        };
	assert_eq!(a_values.len(), SIZE * 8);
        // Witness the bits of the preimage.
	// Allocate each bit.
        let a_bits = a_values.into_iter().enumerate().map(|(i, b)| {AllocatedBit::alloc(cs.namespace(|| format!("a bit {}", i)), b)
       })
            // Convert the AllocatedBits into Booleans
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;
	//===============================
	let r_values = if let Some(r) = self.r{
	r.iter().map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).flatten().map(|b| Some(b)).collect()
        } else {
            vec![None; SIZE * 8]
        };
	assert_eq!(r_values.len(), SIZE * 8);
        // Witness the bits of the preimage.
	// Allocate each bit.
        let r_bits = r_values.into_iter().enumerate().map(|(i, b)| {AllocatedBit::alloc(cs.namespace(|| format!("a bit {}", i)), b)
       })
            // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        //let value = redact(cs.namespace(|| "redacted"), &a_bits, &r_bits)?;
	//let c = multiply(cs.namespace(|| "redact"), &a_bits, &b_bits)?;

	
        // Compute hash = SHA-256d(preimage).
        //let mut hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;
	//hash.extend(value.iter().cloned());
	//concatenate hash and c
        // Expose the vector of 32 boolean variables as compact public inputs.
	let value = redact(cs.namespace(|| "redacted"), &preimage_bits, &a_bits, &r_bits)?;
        multipack::pack_into_inputs(cs.namespace(|| "document-verify"), &value)
	//multipack::pack_into_inputs(cs.namespace(|| "pack hash"), hash')
    }
	
    
}

