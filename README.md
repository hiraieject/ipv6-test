# ipv6-test

IPV6クライアントテスト用のアドレス配布環境

## 事前準備

これを動かすVMに、ブリッジインターフェースを３個追加する

追加したインターフェースのデバイス名を ifconfig で調べて、Makefile のデバイス名定義を書き換える

	example)
	SERVER1_DEV = ens38
	SERVER2_DEV = ens39
	CLIENT_DEV = ens40

make tool_install を実行して、必要なコマンドをインストールする

## サーバーコントロールターゲット

	make start_StatefullDhcp
	# DHCPサーバーからステートフルアドレスを配布
	
	make start_StatelessDhcp
	# DHCPサーバーからステートレスアドレスを配布

	make start_StatelessRdnss
	# RDNSSサーバーからステートレスアドレスを配布

	make start_StatelessRdnss_StatefullDHCP
	# RDNSSサーバーからステートレスアドレス、DHCPサーバーからステートフルアドレスを配布

	make start_StatelessRdnssX2
	# RDNSSサーバーからステートレスアドレスを２系統配布

