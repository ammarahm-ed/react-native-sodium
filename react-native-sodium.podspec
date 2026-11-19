require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name         = "react-native-sodium"
  s.version      = package['version']
  s.summary      = package['description']
  s.license      = package['license']

  s.authors      = package['author']
  s.homepage     = package['homepage']
  s.platform     = :ios, "15.1"

  s.source       = { :git => "https://github.com/lyubo/react-native-sodium.git", :tag => "v#{s.version}" }
  s.source_files  = ["ios/**/*.{h,m,mm}"]

  # libsodium 1.0.20 static xcframework: ios-arm64 (device) and
  # ios-arm64_x86_64-simulator slices.
  s.vendored_frameworks = 'libsodium/libsodium.xcframework'
  # sodium.h does #include "sodium/version.h", so the xcframework headers have
  # to be on the search path.
  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/libsodium/libsodium.xcframework/ios-arm64/Headers"'
  }

  # Pulls in React-Core and, when the New Architecture is enabled, the codegen
  # and TurboModule dependencies plus the RCT_NEW_ARCH_ENABLED flag. Falls back
  # to a plain React-Core dependency on React Native versions without it.
  if respond_to?(:install_modules_dependencies, true)
    install_modules_dependencies(s)
  else
    s.dependency 'React-Core'
  end
  # RCTSodium.m imports MF_Base64Additions.h. This was never declared, so the
  # pod only built inside apps that happened to install Base64 for some other
  # reason.
  s.dependency 'Base64'
end
