rule second_payload_ass2 {
   meta:
      hash1 = "da7d6cebf27b080486d471f56b8145ba2a4ae862fae6e9a8ce0c7ed8ac9a6de1"
   strings:
      $z1 = "ch0nky.chickenkiller.com" fullword wide
      $z2 = "C:\\malware\\ch0nky.txt" fullword wide
      $z3 = "auth=d50fb4bbb04a6a28ec1c56ecbc463510" fullword ascii
      $s1 = "         <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "&computer=" fullword ascii
      $s3 = "&user=" fullword ascii
      $s4 = "&guid=" fullword ascii
      $s5 = "/register.php" fullword wide
      $s6 = "/checkin.php" fullword wide
      $s7 = "ch0nky" fullword ascii
      $s8 = "powershell.exe /c " fullword ascii
      $s9 = "CharToOemBuffA" fullword ascii
      
   condition:
      (uint16(0) == 0x5a4d) and 
      (filesize < 100KB) and
      (3 of ($z*)) or
      (4 of ($s*) and any of ($z*))
}

rule second_payload_ass1 {
   meta:
      hash1 = "68474c5c2279acbda9549451fa10bfdf08e36bb1f683ba83f6dfe18c1bc7c1fd"
   strings:
      $mz = "MZ"
      $s1 = "LoadLibraryA" fullword ascii
      $s2 = "GetWindowDC" fullword ascii
      $s3 = "PlaySoundA" fullword ascii

   condition:
      math.entropy(0, filesize) >= 7 or   
      for any i in (0..(pe.number_of_sections)-1) :                                                                         
      (           
         pe.sections[i].name == "UPX*"  or                                                                                      
         math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7
      )
      $mz at 0 and 
      (filesize > 30MB) and
      (2 of ($s*))
}

rule first_payload {
   meta:
      hash1 = "9d5a1eecd236d61e3242850d0487808091fc5d0db0a3e45be8970bdbf1fdff88"
      hash2 = "61a8246e02492ccdcf4283fd746fb8dfef56053f29e6e62dcaf3075c2c6e6c4f"
   strings:
      $z1 = "ch0nky.chickenkiller.com" wide
      $z2 = "MicrosoftUpdate.exe" fullword wide
      $z3 = "C:\\malware\\ch0nky.txt" fullword wide
      $z4 = "Sorry. You are not a winner" fullword wide
      $z5 = "Congratulations on winning!" fullword wide
      $s1 = "DeleteUrlCacheEntryW" fullword ascii
      $s2 = "URLDownloadToFileW" fullword ascii
      $s3 = "urlmon.dll" fullword ascii
      $s4 = "CreateProcessW" fullword ascii
      $s5 = "SAD!" fullword wide
      $s6 = "WOW!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      (5 of ($z*)) or
      (5 of ($s*) and any of ($z*))
}

rule maldoc {
   meta:
      hash1 = "9b6d84c11470f3873f938a2517a0b935f73258521de9fbaa0213e6e94a041ce2"
      hash2 = "e1edd1835f00026da05761a0be84779ac6383b00872366ebdb8411a5eeb7792f"
   strings:
      $x1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $x4 = "powershell.exe kill -processname winword'" fullword ascii
      $s5 = "://www.brianbaldeck.com\" crs:RawFileName=\"DSC_5822.NEF\" crs:Version=\"11.3\" crs:ProcessVersion=\"6.7\" crs:WhiteBalance=\"As" ascii
      $s6 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s8 = " INCLUDEPICTURE \"https://www.bu.edu/tech/wp-content/themes/bu-tech-2014/images/bu-techweb-logo.png\" \\* MERGEFORMATINET " fullword ascii
      $s9 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s10 = "hell.exe" fullword ascii
      $s11 = "http://www.brianbaldeck.com" fullword ascii
      $s12 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s13 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s14 = "C:\\malware\\ch0nky.txt" fullword ascii
      $s15 = "WScript.Shell" fullword ascii
      $s16 = "adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpRights=\"http://ns.adobe.com/xap/1" ascii
      $s17 = "ell.exe /c " fullword ascii
      $s18 = "s:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http:" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

