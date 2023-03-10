package license

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wenzhenxi/gorsa"
)

// 公钥
var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3J+24OIkIYajQ/xRgG5m
dvCcBkh1wwDy6UnMvxW42UT0TA0nENGjmHmIpkyxUhFMC9f/KHiskuoSURrhMAuz
bcKE/aEmNFfNThm4XNLNo43F7/dROMzB2nXAcRJVjhFiaAdQ1s8vd4grN5fJSVKc
H/4hDIxiN37a6QqyiQCB9+erRSMV5PEnA57PwlOr3+YSJafW55F73pt0XRk6kfAG
Eiy8cugCG294Mc/SX/plRz4eCrjyGo1r4bWw7WxUB/Rt1blALJpLsFaN0M/9vmOM
osw6y4SgljETZO5Hd7rQHDUipXd8g/8l5SoSoV1tNubH8v03dlAbDPZnG+c+Le+c
2wIDAQAB
-----END PUBLIC KEY-----`

var LicenseExpired = errors.New("license is expired.")

// GetID 获取机器码
func GetID() string {
	macStr := GetMac()

	id := fmt.Sprintf("%x", md5.Sum([]byte(macStr)))
	return id
}

// CheckLicense 校验授权
func CheckLicense(file string, key string) ([]string, error) {
	if err := gorsa.RSA.SetPublicKey(publicKey); err != nil {
		return nil, errors.New("unknown exception 1001")
	}

	// 读取license
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("license file not found 1002")
	}

	// base64解码
	data1, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, errors.New("license content is invalid 1003")
	}

	// rsa解密
	id, err := gorsa.RSA.PubKeyDECRYPT(data1)
	if err != nil {
		return nil, errors.New("license content is invalid 1004")
	}
	// 解析授权文件内容
	result := strings.Split(string(id), "###")
	if len(result) < 3 {
		return nil, errors.New("license content is invalid 1005")
	}
	// 机器码不匹配
	if GetID() != result[0] {
		return nil, errors.New("license content is invalid 1006")
	}
	// Key不匹配
	if key != "" && key != result[1] {
		return nil, errors.New("license content is invalid 1007")
	}
	// 已过期
	t, err := time.Parse("2006-01-02", result[2])
	if err != nil {
		return nil, errors.New("license content is invalid 1008")
	}
	if t.Unix()+86400 <= time.Now().Unix() {
		return nil, LicenseExpired
	}
	return result[3:], nil
}

// GetMac 获取Mac
func GetMac() (macAdds string) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("fail to get net interfaces: %v", err)
		return macAdds
	}

	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}

		if len(macAdds) > 0 {
			macAdds = macAdds + "," + macAddr
		} else {
			macAdds = macAddr
		}
	}
	return macAdds
}

// Encrypt 使用公钥加密指定字符串
func Encrypt(data string) (string, error) {
	result, err := gorsa.PublicEncrypt(data, publicKey)
	if err != nil {
		return "", err
	}
	return result, nil
}
