#!/usr/bin/env ruby

require 'rubygems'
require 'r509'
require 'r509/trollop'

puts "starting"

yaml_data = File.read "bin/config.yaml"
conf = R509::Config::CAConfig.from_yaml("test_ca", yaml_data)

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
puts cert.to_pem
