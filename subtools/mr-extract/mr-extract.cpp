#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* SGXSDKのフォルダパスはここで指定。自身の環境に合わせて変更する */
std::string sdk_path = "/opt/intel/sgxsdk/";

/* 署名済みEnclaveイメージファイル名はここで指定。
 * 自身の環境に合わせて変更する */
std::string image_path = "../../enclave.signed.so";


int main()
{
    std::string signing_tool_path = sdk_path + std::string("bin/x64/sgx_sign");
    
    pid_t pid;
    int status;

    pid = fork();

    if(pid == -1)
    {
        std::cerr << "Failed to fork process for sgx_sign." << std::endl;
        exit(1);
    }
    else if(pid == 0)
    {
        char *cmd[] = {
            (char*)"sgx_sign",
            (char*)"dump",
            (char*)"-enclave",
            (char*)image_path.c_str(),
            (char*)"-dumpfile",
            (char*)"tmp.txt",
            NULL
        };

        std::cout << "-------- message from sgx_sign tool --------" << std::endl;
        execv(signing_tool_path.c_str(), cmd);

        std::cerr << "Failed to exec sgx_sign." << std::endl;
        exit(1);
    }

    waitpid(pid, &status, 0);
    std::cout << "--------------------------------------------" << std::endl;

    if(!WIFEXITED(status))
    {
        std::cerr << "Failed to exit sgx_sign successfully." << std::endl;
        exit(1); 
    }

    /* ここまで来ればsgx_signの実行は正常に完了している */
    std::ifstream ifs("tmp.txt");

    if(!ifs)
    {
        std::cerr << "Failed to open dump file." << std::endl;
        exit(1);
    }

    std::string line;
    std::string mrenclave, mrsigner;

    while(getline(ifs, line))
    {
        if(line.find("enclave_css.body.enclave_hash.m") != std::string::npos)
        {
            /* MRENCLAVE値を示す2行を読み取る */
            getline(ifs, line);
            mrenclave += line;
            getline(ifs, line);
            mrenclave += line;
        }
        else if(line.find("mrsigner->value") != std::string::npos)
        {
            /* MRSIGNER値を示す2行を読み取る */
            getline(ifs, line);
            mrsigner += line;
            mrsigner += " ";
            getline(ifs, line);
            mrsigner += line;
        }
    }

    //std::cout << mrenclave << std::endl;
    //std::cout << mrsigner << std::endl;

    ifs.close();

    if(0 != std::remove("tmp.txt"))
    {
        std::cerr << "Failed to delete temporary dump file." << std::endl;
        return 1;
    }

    /* 連続的なHexバイト列に変換 */
    std::stringstream mre_ss, mrs_ss;
    std::string byte_hex;

    mre_ss << mrenclave;
    mrs_ss << mrsigner;

    std::cout << "\nCopy and paste following measurement values into settings.ini." << std::endl;
    std::cout << "\033[32mMRENCLAVE value -> \033[m";

    while(getline(mre_ss, byte_hex, ' '))
    {
        byte_hex.erase(0, 2); //"0x"を削除
        std::cout << byte_hex;
    }

    std::cout << "\n\033[32mMRSIGNER value  -> \033[m";

    while(getline(mrs_ss, byte_hex, ' '))
    {
        byte_hex.erase(0, 2); //"0x"を削除
        std::cout << byte_hex;
    }

    std::cout << "\n" << std::endl;

    return 0;
}