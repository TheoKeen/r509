#!/usr/bin/env ruby

require 'rubygems'
require 'r509'
require 'r509/trollop'
require 'r509/signature_logger'



ops = ARGV[0]
puts ops

puts "starting"


yaml_data = File.read "bin/config.yaml"
#yaml_data = File.read "bin/configsoft.yaml"

conf = R509::Config::CAConfig.from_yaml("test_ca", yaml_data)
#conf = R509::Config::CAConfig.from_yaml("test_ca", yaml_data, ca_root_path: 'c:/')

ca = R509::CertificateAuthority::Signer.new(conf)

ext = []
# you can add extensions in an array. See R509::Cert::Extensions::*
ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)

csr = R509::CSR.new(
    :subject => {
      :CN => 'Keennews.nl',
      :O => 'Keennews',
      :L => 'KeenCity',
      :ST => 'NH',
      :C => 'NL'
    }
  )

  
  cert = ca.sign(
    :csr => csr,
    :extensions => ext
  )


#Display Cert
slog = R509::SignatureLogger.new(conf)
slog.logsignature(cert)
#myvar = slog.listlogs


