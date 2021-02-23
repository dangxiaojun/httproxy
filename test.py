import requests


def get(server, host):
    try:
        res = requests.get(server, headers={"Host": host})
        print(res.status_code)
    except Exception as e:
        pass


if __name__ == '__main__':
    get("http://127.0.0.1", "www.google.com")
