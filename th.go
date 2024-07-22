package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

func encrypter(fname string) {
	plainText, err := os.ReadFile(fname + ".exe")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	test := "F45B6BDB200197F166262116319A6ECE"

	block, err := aes.NewCipher([]byte(test))
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("nonce  err: %v", err.Error())
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	err = os.WriteFile(fname+".bin", cipherText, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
}

func encrypt_string(plain_text string) string {
	test := "F45B6BDB200197F166262116319A6ECE"

	block, err := aes.NewCipher([]byte(test))
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("nonce  err: %v", err.Error())
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plain_text), nil)
	return string(cipherText)
}

func services_list(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "query", "-t", "all")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
	cover_tracks("assets/sdelete.bin", fname)
}

func tcp_connection_list(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "-a", "-c")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	cover_tracks("assets/sdelete.bin", fname)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func autorun_programs_list(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "-s", "-m", "-h", "-c", "-a", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
	cover_tracks("assets/sdelete.bin", fname)
}

func loggedon_users(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "-c")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
	cover_tracks("assets/sdelete.bin", fname)
}

func load_order_programs(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "-c")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
	cover_tracks("assets/sdelete.bin", fname)
}

func process_tree(fname string) {
	cipherText, err := os.ReadFile(fname + ".bin")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-nobanner", "-t")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
	cover_tracks("assets/sdelete.bin", fname)
}

func get_security_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-EventLog", "-LogName", "Security", "|", "Select-Object", "-Property", "EntryType", ",", "TimeGenerated,", "Source,", "EventID,", "Category,", "Message")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/security.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/security.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_powershell_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-PowerShell/Operational", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/powershell.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/powershell.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_schedule_task_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-TaskScheduler/Operational", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/schedule_task.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/schedule_task.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_remote_desktop_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/remote_desktop.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/remote_desktop.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func delete_created_exe(file_path string) {
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "|", "Select-Object", "*")
	stdout, _ := cmd.Output()
	fmt.Println(stdout)
}

func get_windows_defender_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-Windows Defender/Operational", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/windows_defender.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/windows_defender.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_windows_firewall_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/windows_firewall.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/windows_firewall.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_windows_time_service_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-WinEvent", "Microsoft-Windows-Time-Service/Operational", "|", "Select-Object", "*")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/time_service.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/time_service.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func get_office_log() {
	//cipherText, err := os.ReadFile(fname + ".bin")
	//if err != nil {
	//	log.Fatalf("read file err: %v", err.Error())
	//}
	//binary := decrypt_text(string(cipherText))

	//os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command("powershell", "Get-EventLog", "-LogName", "OAlerts", "|", "Select-Object", "-Property", "EntryType", ",", "TimeGenerated,", "Source,", "EventID,", "Category,", "Message")
	stdout, err := cmd.Output()
	err = os.WriteFile("./assets/OAlerts.txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile("./assets/OAlerts.enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func decrypt_text(cipherText string) string {
	test := "F45B6BDB200197F166262116319A6ECE"
	block, err := aes.NewCipher([]byte(test))
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}
	nonce := []byte(cipherText)[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, []byte(cipherText), nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}
	return string(plainText)
}

func cover_tracks(fname string, purge_name string) {
	cipherText, err := os.ReadFile(fname)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	binary := decrypt_text(string(cipherText))

	os.WriteFile(fname+".exe", []byte(binary), 0777)
	cmd := exec.Command(fname+".exe", "-accepteula", "-p", "5", "-q", "-r", "-nobanner", "-f", purge_name+".exe")
	stdout, err := cmd.Output()
	err = os.WriteFile(fname+".txt", stdout, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
	err = os.WriteFile(fname+".enc", []byte(encrypt_string(string(stdout))), 0777)
	//fmt.Println(decrypt_text((encrypt_string(string(stdout)))))
}

func main() {
	//encrypter("assets/tcpvcon64")
	//encrypter("assets/autorunsc")
	//encrypter("assets/handle")
	//encrypter("assets/LoadOrdC")
	//encrypter("assets/pipelist")
	//encrypter("assets/logonsessions")
	//encrypter("assets/pslist")
	//encrypter("assets/PsLoggedon")
	//encrypter("assets/psloglist")
	//encrypter("assets/tcpvcon")
	//encrypter("assets/sdelete")
	go services_list("./assets/PsService")
	go tcp_connection_list("./assets/tcpvcon")
	go autorun_programs_list("./assets/autorunsc")
	go loggedon_users("./assets/PsLoggedon")
	go load_order_programs("./assets/LoadOrdC")
	go process_tree("./assets/pslist")
	go get_security_log()
	go get_powershell_log()
	go get_schedule_task_log()
	go get_office_log()
	go get_windows_defender_log()

	select {}
	//log_list()
}
