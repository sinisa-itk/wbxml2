from distutils.core import setup
from Cython.Build import cythonize

ext = cythonize("*.pyx")
wbxml_binding = ext[0]

wbxml_binding.library_dirs.append(r"c:\dev\activesync_lenny\pywbxml-0.1\src")
wbxml_binding.include_dirs.append(r"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include")
wbxml_binding.library_dirs.append(r"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Lib")
wbxml_binding.libraries.append("libwbxml2")

wbxml_binding.include_dirs.append("c:/dev/activesync_lenny/libwbxml/trunk/src")
wbxml_binding.include_dirs.append("c:/dev/activesync_lenny/libwbxml/trunk/win32/missing")
wbxml_binding.include_dirs.append("c:/dev/activesync_lenny/libwbxml/trunk/win32/expat")
wbxml_binding.define_macros.append(("WBXML_SUPPORT_WML", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_WTA", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_SI", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_SL", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_CO", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_PROV", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_EMN", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_DRMREL", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_OTA_SETTINGS", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_SYNCML", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_WV", None))
wbxml_binding.define_macros.append(("WBXML_SUPPORT_AIRSYNC", None))
wbxml_binding.define_macros.append(("WBXML_ENCODER_USE_STRTBL", None))
wbxml_binding.define_macros.append(("HAVE_EXPAT", None))
wbxml_binding.define_macros.append(("WBXML_WRAPPERS", None))

setup(
  name = 'wbxml bindings',
  ext_modules = ext
)