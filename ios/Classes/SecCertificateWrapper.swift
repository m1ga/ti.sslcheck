//
//  SecCertificateWrapper.swift
//  ti.sslcheck
//
//  Created by Hans Knöchel on 24.08.22.
//

import Foundation

enum FingerprintType {
    case SHA1
    case MD5
}

@objc
class SecCertificateWrapper : NSObject {
    
    var data: Data
    var cert: SecCertificate
    
    // Initialize with a data object from the "DeveloperCertificates"
    // array (see WrapperImplementation.swift)
  @objc
  init(data:Data) {
        self.cert = SecCertificateCreateWithData(nil, data as CFData)!
        // Use this later for parsing the date details from the cert
        self.data = data
    }
    
    // The certificate name
  @objc
    var commonName : String {
      var commonNameString: CFString!
      let _ = SecCertificateCopyCommonName(cert, &commonNameString)
      
      return String(commonNameString)
    }

    // Return a tuple with both notValidBefore and notValidAfter dates
  @objc
  var validDates: NSDictionary? {
        guard let decodedString = String( data: self.data, encoding: .ascii ) else { return nil }
        var foundWWDRCA         = false
        var notValidBeforeDate  = ""
        var notValidAfterDate   = ""
        
        decodedString.enumerateLines { (line, _) in
            
            if foundWWDRCA && (notValidBeforeDate.isEmpty || notValidAfterDate.isEmpty) {
                let certificateData = line.prefix(13)
                if notValidBeforeDate.isEmpty && !certificateData.isEmpty {
                    notValidBeforeDate = String(certificateData)
                } else if notValidAfterDate.isEmpty && !certificateData.isEmpty {
                    notValidAfterDate = String(certificateData)
                }
            }
            
            if line.contains("Apple Worldwide Developer Relations Certification Authority") { foundWWDRCA = true }
        }
        
      return ["notValidBeforeDate": self.format(notValidBeforeDate), "notValidAfterDate": self.format(notValidAfterDate)]
    }
    
    // Some convenience properties for access to the notValidBefore and notValidAfter
    // dates in various formats
  @objc
    var notValidAfterUnixDate : Double {
      if let validDates = validDates {
        return (validDates["notValidAfter"] as! Date).timeIntervalSince1970
      }
      return  0
    }
    
  @objc
    var notValidAfterUnixDateAsString : String {
        return String(self.notValidAfterUnixDate)
    }

  @objc
    var notValidBeforeUnixDate : Double {
      if let validDates = validDates {
        return (validDates["notValidBefore"] as! Date).timeIntervalSince1970
      }

        return 0
    }
    
  @objc
    var notValidBeforeUnixDateAsString : String {
        return String(self.notValidBeforeUnixDate)
    }
    
    // Create a static data formatter just for convenience
    static let certificateDateFormatter : DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyMMddHHmmssZ"
        return formatter
    }()

    // Provide a format function to help shorten the code where date
    // formatting is performed
    func format(_ date:String) -> Date {
        return SecCertificateWrapper.certificateDateFormatter.date(from: date)!
    }

}
