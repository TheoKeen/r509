require 'nokogiri'
require 'base64'
require 'date'
require 'xmldsig'

module R509

    def foo2
        puts "foo"
      end
      module_function :foo2

class SignatureLogger

  @@currentsignature = 0

    def initialize(ca)
        @ca = ca
        currentsignature()
      end
  
    def currentsignature
      if softhsmused() && @@currentsignature = 0
          @@currentsignature = lastsignaturefromlogs
      end
      return @@currentsignature
    end

    def signaturenr_fromfilename(filename)
      filename.slice! @ca.logdir + @ca.ca_cert.fingerprint('sha1') + "_"
      filename.slice! ".xml"
      return filename
    end

    def filename_fromsignaturenr(signaturenr)
      @ca.logdir + @ca.ca_cert.fingerprint('sha1') + "_" + signaturenr.to_s + ".xml"
    end

    def lastsignaturefromlogs
      lastsignature=0
      tmplist = listlogs
      if tmplist.nil?
        lastsignature = 0
      else
        dirlist = []
        tmplist.each do |filename|
          dirlist.push(signaturenr_fromfilename(filename).to_i)
        end
        dirlist.sort!
        lastsignature = dirlist.last
      end
      
      return lastsignature 
    end

    def listlogs
      filter = @ca.logdir + @ca.ca_cert.fingerprint('sha1') + "_*.xml"
      Dir[filter].sort
    end

    def softhsmused

      #Retrieving softhsm is not working (easily.. skipping)
 
     return true
      #keyname = @ca.ca_cert.key.key_name
      #retval = false

      #if "SoftHSM".to_s.in? "bla"
      #  retval = true
      #end
      #return retval
    end

    def checkcurrentsignature
     if softhsmused()
        @@currentsignature = @@currentsignature.to_i + 1
     end
    return @@currentsignature      
    end

    def logsignature(signedobject)
        builder = Nokogiri::XML::Builder.new do |xml|
            xml.root {
              xml.CASignOperation {
                  xml.SignatureCounter checkcurrentsignature()
                  xml.PreviousHash
                  xml.user ENV['USER']
                  xml.date DateTime.now.new_offset(0)
                  addx509data(signedobject,xml)
              }
              xml.Signature('xmlns' => 'http://www.w3.org/2000/09/xmldsig#') {
                xml.SignedInfo{
                  xml.CanonicalizationMethod('Algorithm' => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                  xml.SignatureMethod('Algorithm' => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                  xml.Reference('URI' => ''){
                    xml.Transforms{
                      xml.Transform('Algorithm' => "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
                    }
                    xml.DigestMethod('Algorithm' => "http://www.w3.org/2001/04/xmlenc#sha256")
                    xml.DigestValue
                  }
                }#xml.SignedInfo
              xml.SignatureValue
              xml.KeyInfo{
                xml.X509Data
              }
              } #xml.Signature
            }
          end
          unsigned_document = Xmldsig::SignedDocument.new(builder.to_xml)
          signed_xml = unsigned_document.sign(@ca.ca_cert.key.key)

          File.write(filename_fromsignaturenr(@@currentsignature), signed_xml)
        
    end

    private
    def addx509data(signedobject, xml)
      puts signedobject.class

      case signedobject
      when R509::Cert
        addx509cert(signedobject, xml)
      when R509::CSR
        puts "TODO"
      when R509::SignedList
        puts "TODO"
      end
    end

    def addx509cert(x509cert, xml)
      xml.X509Data {
        xml.X509Certificate Base64.encode64(x509cert.to_der)
        xml.X509SubjectName x509cert.subject
       }
      return xml
    end


end

end
  