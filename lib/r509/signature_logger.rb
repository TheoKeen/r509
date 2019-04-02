require 'nokogiri'
require 'base64'
require 'date'
require 'xmldsig'

module R509

class SignatureListItem
  attr_accessor :signaturenr, :filename, :x509subjectname, :signaturedate

  def initialize(signaturenr, filename, x509subjectname, signaturedate)
    @signaturenr = signaturenr
    @filename   = filename
    @x509subjectname = x509subjectname
    @signaturedate = signaturedate
  end
  

end

class SignatureLogger
  @@signaturelist
  @@currentsignature = 0

    def initialize(ca)
        @ca = ca
        @@signaturelist = GetSignatureList()
        currentsignature()
        PrintLastSignatures(3)
        puts "init logger done."
      end
  
    def PrintLastSignatures(limit)
      unless @@signaturelist.nil?
        if limit.to_i > @@signaturelist.count 
          limit = @@signaturelist.count
        end
        for counter in 0..(limit -1)
          puts @@signaturelist[counter].signaturenr.to_s.rjust(3, "0") + " | " + @@signaturelist[counter].signaturedate  + " | " +  @@signaturelist[counter].x509subjectname
        end
      end
    end

    def currentsignature
      if softhsmused() && @@currentsignature = 0
          @@currentsignature =  @@signaturelist.first.signaturenr
      end
      return @@currentsignature
    end

    def filename_fromsignaturenr(signaturenr)
      @ca.logdir + @ca.ca_cert.fingerprint('sha1') + "_" + signaturenr.to_s + ".xml"
    end

    def listlogs
      filter = @ca.logdir + @ca.ca_cert.fingerprint('sha1') + "_*.xml"
      Dir[filter].sort
    end

    def GetSignatureList
      dirlist = listlogs
      signaturelist = []

      unless dirlist.nil?
        dirlist.each do |filename|
          xmldoc = Nokogiri::XML(File.open(filename))
          xmlnode = xmldoc.at_xpath("//date")
          signaturedate =  xmlnode.text if xmlnode
          xmlnode = xmldoc.at_xpath("//SignatureCounter")
          signaturecounterinxml = xmlnode.text if xmlnode
          xmlnode = xmldoc.at_xpath("//X509SubjectName")
          x509subjectname = xmlnode.text if xmlnode
          listitem = SignatureListItem.new(signaturecounterinxml.to_i, filename, x509subjectname, signaturedate)
          signaturelist.push(listitem)
        end
        signaturelist = signaturelist.sort_by { |a| [ a.signaturenr] }.reverse 
        return signaturelist
  
      end
    end

    def softhsmused
      #Retrieving softhsm is not working (easily.. skipping)
     return true
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
      case signedobject
      when R509::Cert
        addx509cert(signedobject, xml)
      when R509::SignedList
        puts "TODO"
      when R509::CSR
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
  