from config import Config

class ServerClient:
    def __init__(self):
        self.server_url = Config.SERVER_URL

    def get_dids(self):
        pass

    def get_did(self, did):
        pass

    def get_resources(self, did):
        pass

    def get_resource(self, did):
        pass

    def get_whois(self, did):
        pass

    def get_witness_file(self, did):
        pass