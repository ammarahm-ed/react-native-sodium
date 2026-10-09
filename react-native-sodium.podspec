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
  s.source_files  = ["ios/**/*.{h,m}","libsodium/libsodium-ios/**/*.{h,m}"]

  s.vendored_libraries = 'libsodium/libsodium-ios/lib/libsodium.a'
    # sodium.h does #include "sodium/version.h", so the vendored include dir has
  # to be on the search path. (The previous value interpolated '#{s.name}'
  # inside single quotes, so it was a literal, non-existent path.)
  s.xcconfig = {
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/libsodium/libsodium-ios/include"'
  }

  s.dependency 'React-Core'
  # RCTSodium.m imports MF_Base64Additions.h. This was never declared, so the
  # pod only built inside apps that happened to install Base64 for some other
  # reason.
  s.dependency 'Base64'
end
