// Copyright (c) 2021 The Chromium Embedded Framework Authors. All rights
// reserved. Use of this source code is governed by a BSD-style license that
// can be found in the LICENSE file.
//
// ---------------------------------------------------------------------------
//
// This file was generated by the CEF translator tool. If making changes by
// hand only do so within the body of existing method and function
// implementations. See the translator.README.txt file in the tools directory
// for more information.
//
// $hash=a3876890dd91d430af51c1f0ce639e8449453bc3$
//

#ifndef CEF_LIBCEF_DLL_CTOCPP_SSLSTATUS_CTOCPP_H_
#define CEF_LIBCEF_DLL_CTOCPP_SSLSTATUS_CTOCPP_H_
#pragma once

#if !defined(WRAPPING_CEF_SHARED)
#error This file can be included wrapper-side only
#endif

#include "include/capi/cef_ssl_status_capi.h"
#include "include/cef_ssl_status.h"
#include "libcef_dll/ctocpp/ctocpp_ref_counted.h"

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class CefSSLStatusCToCpp : public CefCToCppRefCounted<CefSSLStatusCToCpp,
                                                      CefSSLStatus,
                                                      cef_sslstatus_t> {
 public:
  CefSSLStatusCToCpp();
  virtual ~CefSSLStatusCToCpp();

  // CefSSLStatus methods.
  bool IsSecureConnection() OVERRIDE;
  cef_cert_status_t GetCertStatus() OVERRIDE;
  cef_ssl_version_t GetSSLVersion() OVERRIDE;
  cef_ssl_content_status_t GetContentStatus() OVERRIDE;
  CefRefPtr<CefX509Certificate> GetX509Certificate() OVERRIDE;
};

#endif  // CEF_LIBCEF_DLL_CTOCPP_SSLSTATUS_CTOCPP_H_
