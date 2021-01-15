package confidential.demo.map;

public class Server {
	public static void main(String[] args) throws NumberFormatException {
		new KVStoreServer(Integer.parseInt(args[0]));
	}
}
