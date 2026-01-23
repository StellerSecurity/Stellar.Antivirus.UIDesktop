#!/bin/bash

# Tauri Icon Generator Script
# Usage: ./generate-icons.sh <path-to-your-icon.png>

if [ -z "$1" ]; then
    echo "Usage: ./generate-icons.sh <path-to-your-icon.png>"
    echo "Example: ./generate-icons.sh ~/Desktop/my-icon.png"
    exit 1
fi

SOURCE_ICON="$1"
ICONS_DIR="src-tauri/icons"

if [ ! -f "$SOURCE_ICON" ]; then
    echo "Error: File not found: $SOURCE_ICON"
    exit 1
fi

echo "Generating icons from: $SOURCE_ICON"
echo "Output directory: $ICONS_DIR"

# Create icons directory if it doesn't exist
mkdir -p "$ICONS_DIR"

# Generate PNG icons in various sizes using sips (macOS built-in)
echo "Generating PNG icons..."
sips -z 32 32 "$SOURCE_ICON" --out "$ICONS_DIR/32x32.png"
sips -z 128 128 "$SOURCE_ICON" --out "$ICONS_DIR/128x128.png"
sips -z 256 256 "$SOURCE_ICON" --out "$ICONS_DIR/128x128@2x.png"
sips -z 1024 1024 "$SOURCE_ICON" --out "$ICONS_DIR/icon.png"

# Generate macOS .icns file
echo "Generating macOS icon (icon.icns)..."
mkdir -p "$ICONS_DIR/icon.iconset"

# Create all required sizes for .icns
sips -z 16 16 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_16x16.png"
sips -z 32 32 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_16x16@2x.png"
sips -z 32 32 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_32x32.png"
sips -z 64 64 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_32x32@2x.png"
sips -z 128 128 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_128x128.png"
sips -z 256 256 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_128x128@2x.png"
sips -z 256 256 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_256x256.png"
sips -z 512 512 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_256x256@2x.png"
sips -z 512 512 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_512x512.png"
sips -z 1024 1024 "$SOURCE_ICON" --out "$ICONS_DIR/icon.iconset/icon_512x512@2x.png"

# Convert iconset to .icns
iconutil -c icns "$ICONS_DIR/icon.iconset" -o "$ICONS_DIR/icon.icns"

# Clean up iconset directory
rm -rf "$ICONS_DIR/icon.iconset"

# For Windows .ico, we'll need to use a different approach
# For now, we can use sips to create a basic .ico (macOS can do this)
echo "Generating Windows icon (icon.ico)..."
# Note: macOS sips can create .ico but it's limited. For best results, use an online converter or ImageMagick
# For now, we'll copy the 256x256 as a placeholder
cp "$ICONS_DIR/128x128@2x.png" "$ICONS_DIR/icon.ico" 2>/dev/null || echo "Note: .ico generation may need manual conversion"

echo ""
echo "✅ Icons generated successfully!"
echo ""
echo "Generated files:"
echo "  - $ICONS_DIR/32x32.png"
echo "  - $ICONS_DIR/128x128.png"
echo "  - $ICONS_DIR/128x128@2x.png"
echo "  - $ICONS_DIR/icon.png (1024x1024)"
echo "  - $ICONS_DIR/icon.icns (macOS)"
echo ""
echo "⚠️  Note: For Windows .ico file, you may need to:"
echo "   1. Use an online converter (e.g., convertio.co, cloudconvert.com)"
echo "   2. Or install ImageMagick: brew install imagemagick"
echo "   3. Then run: convert icon.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico"
