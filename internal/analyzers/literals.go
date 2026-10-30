package analyzers

// String literals shared by the in-process analyzers and their converters.
const (
	// metaInfDir is the archive directory that carries the signing material.
	metaInfDir = "META-INF"

	// Generic boolean/state values used by more than one analyzer.
	valueNone = "none"
	valueFull = "full"

	// Anti-analysis marker kinds.
	markerRoot        = "root"
	markerEmulator    = "emulator"
	markerAntiDebug   = "anti-debug"
	markerFrida       = "frida"
	markerXposed      = "xposed"
	markerSubstrate   = "substrate"
	markerDynamicCode = "dynamic-code"
	markerReflection  = "reflection"
	markerIntegrity   = "integrity"

	// Anti-analysis finding titles.
	titleRootDetected      = "App detects root"
	titleEmulatorDetected  = "App detects an emulator"
	titleDebuggerDetected  = "App detects an attached debugger"
	titleFridaDetected     = "App detects or uses Frida"
	titleXposedDetected    = "App detects or uses Xposed"
	titleSubstrateDetected = "App detects or uses Cydia Substrate"
	titleDynamicCode       = "App loads code dynamically"
	titleIntegrityCheck    = "App checks its own package signature"

	// Marker strings that the ELF string scan compares by name.
	markerTracerPid           = "TracerPid"
	markerIsDebuggerConnected = "isDebuggerConnected"
	markerAndroidDebug        = "android.os.Debug"

	// Manifest component kind and a well-known Maven group.
	componentKindProvider = "provider"
	firebaseGroup         = "com.google.firebase"
)
