#!/bin/zsh
set -e

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR"

APP_NAME="Claude IP 检测"
EXEC_NAME="ClaudeIPChecker"
BUILD_DIR="$SCRIPT_DIR/build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "==> 清理并创建应用包目录结构..."
rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

echo "==> 生成应用高清图标 AppIcon.icns..."
ICONSET_DIR="$BUILD_DIR/AppIcon.iconset"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"

swiftc -target arm64-apple-macosx14.0 -module-cache-path /tmp/clang-module-cache "$SCRIPT_DIR/Sources/IconGenerator.swift" -o "$BUILD_DIR/icon_gen"
"$BUILD_DIR/icon_gen" "$BUILD_DIR/icon_1024.png"
rm -f "$BUILD_DIR/icon_gen"

sips -z 16 16     "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_16x16.png" >/dev/null
sips -z 32 32     "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_16x16@2x.png" >/dev/null
sips -z 32 32     "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_32x32.png" >/dev/null
sips -z 64 64     "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_32x32@2x.png" >/dev/null
sips -z 128 128   "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_128x128.png" >/dev/null
sips -z 256 256   "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
sips -z 256 256   "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_256x256.png" >/dev/null
sips -z 512 512   "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
sips -z 512 512   "$BUILD_DIR/icon_1024.png" --out "$ICONSET_DIR/icon_512x512.png" >/dev/null
cp "$BUILD_DIR/icon_1024.png" "$ICONSET_DIR/icon_512x512@2x.png"

iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/AppIcon.icns"
rm -rf "$ICONSET_DIR" "$BUILD_DIR/icon_1024.png"

echo "==> 编译原生 Swift 客户端二进制..."
swiftc -O -target arm64-apple-macosx14.0 -module-cache-path /tmp/clang-module-cache \
  "$SCRIPT_DIR/Sources/NetworkDetector.swift" \
  "$SCRIPT_DIR/Sources/AppMain.swift" \
  -framework Cocoa \
  -framework WebKit \
  -o "$MACOS_DIR/$EXEC_NAME"

echo "==> 拷贝内置 UI 资源..."
cp "$SCRIPT_DIR/Resources/index.html" "$RESOURCES_DIR/index.html"

echo "==> 生成 Info.plist..."
cat > "$CONTENTS_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleDisplayName</key>
    <string>Claude IP 检测</string>
    <key>CFBundleExecutable</key>
    <string>$EXEC_NAME</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>coffee.net.ip.claude.mac</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Claude IP 检测</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF

echo "==> 执行本地 Ad-hoc 签名..."
codesign --force --deep --sign - "$APP_BUNDLE"

echo "==> 构建完成: $APP_BUNDLE"
