package state

import "golang.org/x/sys/windows"

// restrict replaces the directory's inherited permissions with full control
// for SYSTEM and Administrators only, inherited by everything created inside.
func restrict(dir string, admins bool) error {
	if !admins {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
