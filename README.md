# ZapSSL Project

A cross-platform application with embedded icon resources.

## Features

- Embedded application icons for both Windows (.ico) and other platforms (.png)
- Self-contained executable with no external icon dependencies
- Cross-platform support

## Building

### Windows
1. Ensure `resources.rc` and `app_icon.ico` are in the project directory
2. Include `resources.rc` in your build system:
   ```cmake
   if(WIN32)
     add_executable(MyApp main.cpp resources.rc)
   endif()
   ```

### Other Platforms
1. Generate the embedded PNG header:
   ```bash
   python convert_png_to_header.py app_icon.png app_icon.png.h
   ```
2. Include the generated header in your build

## Icon Embedding

The application uses embedded icons:

```cpp
// Windows
SetIcon(wxICON(app_icon));

// Other platforms
#include "app_icon.png.h"
wxMemoryInputStream istream(app_icon_png, app_icon_png_size);
wxImage image(istream, wxBITMAP_TYPE_PNG);
SetIcon(wxIcon(wxBitmap(image)));
```

## Requirements

- wxWidgets 3.0+
- Python 3.x (for PNG conversion)
- Windows: Resource compiler (windres or MSVC)

## License

MIT License - see LICENSE file for details
