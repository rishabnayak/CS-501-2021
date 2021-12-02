import os 
import argparse
import hashlib




def decrypt_file(f_path):
    # suffix appended to encrypted file 
    suffix = '.ch0nk'
    assert f_path.endswith(suffix)
    with open(f_path, 'rb') as f:
        data = f.read()
    
    
    # hashlib.sha256("IAmAHint!").digest()
    # Decrypt the data!
    decrypted_data = None
    # make sure there is data to be written
    assert decrypted_data
    # drop the ch0nk suffix
    with open(f_path[:-1 * len(suffix)], 'wb+') as f:
        f.write(decrypted_data)    



if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument("filepath", help="Path to encrypted file")
    p_args = argparse.parse_args()
    f_path = p_args.filepath
    decrypt_file(f_path)