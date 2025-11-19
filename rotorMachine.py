# CIIC 5018-050 - Cryptography and Network Security
# Project - Hybrid Cryptosystem using Rotor Machine and DES Encryption
# Part 1: Rotor Machine
# Simulation of a 3-rotor cipher machine with encryption and decryption.
# Authors: Christian Medina Diaz & Edjoel Colon Nogueras

class Rotor:
    # Represents a single rotor.
    # Each rotor performs a substitution cipher and can rotate.
    def __init__(self, wiring, notch_position=None):
        self.wiring = wiring.upper()
        self.reverse_wiring = self.create_reverse_wiring()
        self.position = 0
        self.notch_position = notch_position if notch_position else 25
        
    def create_reverse_wiring(self):
        reverse = [''] * 26
        for i, char in enumerate(self.wiring):
            reverse[ord(char) - ord('A')] = chr(i + ord('A'))
        return ''.join(reverse)
    
    def encrypt(self, char_index):
        shifted_index = (char_index + self.position) % 26
        output = self.wiring[shifted_index]
        output_index = ord(output) - ord('A')
        return (output_index - self.position) % 26
    
    def decrypt(self, char_index):
        shifted_index = (char_index + self.position) % 26
        output = self.reverse_wiring[shifted_index]
        output_index = ord(output) - ord('A')
        return (output_index - self.position) % 26
    
    def rotate(self):
        at_notch = (self.position == self.notch_position)
        self.position = (self.position + 1) % 26
        return at_notch
    
    def set_position(self, position):
        self.position = position % 26
    
    def get_position(self):
        return chr(self.position + ord('A'))

class RotorMachine:
    # 3-rotor cipher machine w encryption and decryption.
    def __init__(self, rotor1_wiring, rotor2_wiring, rotor3_wiring):
        self.rotor1 = Rotor(rotor1_wiring, notch_position=16)  # Q position
        self.rotor2 = Rotor(rotor2_wiring, notch_position=4)   # E position
        self.rotor3 = Rotor(rotor3_wiring, notch_position=21)  # V position
        self.initial_positions = [0, 0, 0]
        
    def set_positions(self, pos1, pos2, pos3):
        self.rotor1.set_position(pos1)
        self.rotor2.set_position(pos2)
        self.rotor3.set_position(pos3)
        self.initial_positions = [pos1, pos2, pos3]
    
    def reset(self):
        self.rotor1.set_position(self.initial_positions[0])
        self.rotor2.set_position(self.initial_positions[1])
        self.rotor3.set_position(self.initial_positions[2])
    
    def rotate_rotors(self):
        rotor2_at_notch = (self.rotor2.position == self.rotor2.notch_position)
        rotor1_at_notch = self.rotor1.rotate()
        
        if rotor1_at_notch or rotor2_at_notch:
            rotor2_at_notch_after = self.rotor2.rotate()
            
            if rotor2_at_notch:
                self.rotor3.rotate()
    
    def encrypt_char(self, char):
        if not char.isalpha():
            return char
        
        char = char.upper()
        self.rotate_rotors()        
        char_index = ord(char) - ord('A')
        
        char_index = self.rotor1.encrypt(char_index)
        char_index = self.rotor2.encrypt(char_index)
        char_index = self.rotor3.encrypt(char_index)
        
        char_index = 25 - char_index
        
        char_index = self.rotor3.decrypt(char_index)
        char_index = self.rotor2.decrypt(char_index)
        char_index = self.rotor1.decrypt(char_index)
        return chr(char_index + ord('A'))
    
    def encrypt(self, message):
        self.reset()
        encrypted = ''
        for char in message:
            encrypted += self.encrypt_char(char)
        return encrypted
    
    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
    
    def get_rotor_positions(self):
        return f"{self.rotor3.get_position()}{self.rotor2.get_position()}{self.rotor1.get_position()}"

def show_rotor_machine():
    print("=" * 75)
    print("                                 ROTOR MACHINE")
    print("=" * 75)
    print()
    
    ROTOR_I_WIRING   = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    ROTOR_II_WIRING  = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    ROTOR_III_WIRING = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    
    machine = RotorMachine(ROTOR_I_WIRING, ROTOR_II_WIRING, ROTOR_III_WIRING)
    machine.set_positions(0, 0, 0)
    
    print("Configuration:")
    print(f"  Rotor 1   (Right): {ROTOR_I_WIRING}")
    print(f"  Rotor 2  (Middle): {ROTOR_II_WIRING}")
    print(f"  Rotor 3    (Left): {ROTOR_III_WIRING}")
    print(f"  Initial Positions: AAA")
    print()
    
    messages = ["HOPE", "HELLO", "NEW YEAR"]
    
    print("=" * 75)
    print("                     ENCRYPTION AND DECRYPTION PROCESS")
    print("=" * 75)
    print()
    results = []
    
    for msg in messages:
        clean_message = msg.replace(" ", "")
        machine.reset()
        encrypted = machine.encrypt(clean_message)
        machine.reset()
        decrypted = machine.decrypt(encrypted)
        
        results.append({
            'original': msg,
            'encrypted': encrypted,
            'decrypted': decrypted
        })
        print(f"Plain Text: {msg}")
        print(f"  Encrypted: {encrypted}")
        print(f"  Decrypted: {decrypted}")
        print(f"  Verification: {'SUCCESS' if decrypted == clean_message else 'FAILED'}")
        print()
    
    print("=" * 75)
    print("                             OBTAINED RESULTS")
    print("=" * 75)
    print()
    print(f"{'Plain Text':<20} {'Encrypted Text':<20} {'Decrypted Text':<20}")
    print("-" * 75)
    for result in results:
        print(f"{result['original']:<20} {result['encrypted']:<20} {result['decrypted']:<20}")
    print()
    
    print("=" * 75)
    print("                         ROTOR STEP DEMONSTRATION")
    print("=" * 75)
    print()
    machine.reset()
    print(f"{'Step':<6} {'Input':<8} {'Rotor Pos':<12} {'Output':<8}")
    print("-" * 40)
    for i, char in enumerate("HELLOWORLD", 1):
        pos_before = machine.get_rotor_positions()
        encrypted = machine.encrypt_char(char)
        print(f"{i:<6} {char:<8} {pos_before:<12} {encrypted:<8}")
    
    print()
    print("=" * 75)
    print("                                 EXPLANATION")
    print("=" * 75)
    print("""
1. Rotor Rotation: Before each character is encrypted, the rightmost rotor
   (Rotor 1) advances one position. When it completes a full rotation,
   it triggers the middle rotor to advance, and so on.

2. Encryption Path: Each character passes through all three rotors from
   right to left, reflects off a 'reflector', then passes back through
   the rotors from left to right.

3. Reciprocal Property: Due to the reflector and rotor design, encrypting
   the ciphertext with the same settings produces the original message.
   This means encryption and decryption use the same process.

4. Security:
   - The complex wiring of each rotor
   - The continuously changing rotor positions
   - The reflector ensuring reciprocal encryption
   - The total number of possible settings (26³ = 17,576 positions)
    
          """)

if __name__ == "__main__":
    show_rotor_machine()