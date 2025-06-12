import os
import sys

def png_to_header(png_path, header_path):
    with open(png_path, 'rb') as png_file:
        png_data = png_file.read()

    with open(header_path, 'w') as header_file:
        header_file.write("#ifndef APP_ICON_PNG_H\n")
        header_file.write("#define APP_ICON_PNG_H\n\n")
        header_file.write("const unsigned char app_icon_png[] = {\n")

        # Write 16 bytes per line
        for i in range(0, len(png_data), 16):
            chunk = png_data[i:i+16]
            line = ", ".join(f"0x{byte:02X}" for byte in chunk)
            header_file.write(f"    {line},\n")

        header_file.write("};\n\n")
        header_file.write(f"const unsigned int app_icon_png_size = {len(png_data)};\n\n")
        header_file.write("#endif // APP_ICON_PNG_H\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_png_to_header.py <input.png> <output.h>")
        sys.exit(1)

    png_path = sys.argv[1]
    header_path = sys.argv[2]

    if not os.path.exists(png_path):
        print(f"Error: Input file '{png_path}' not found")
        sys.exit(1)

    png_to_header(png_path, header_path)
    print(f"Successfully converted {png_path} to {header_path}")
