unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.StdCtrls,
  Dialogs, WinSock, ComCtrls, ExtCtrls, Menus, ImgList, System.ImageList,
  ShellApi, Vcl.Samples.Spin;

const
  MAX_PACKET_SIZE = $10000;
  SIO_RCVALL = $98000001;
  WSA_VER = $202;
  MAX_ADAPTER_NAME_LENGTH        = 256;
  MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
  MAX_ADAPTER_ADDRESS_LENGTH     = 8;
  IPHelper = 'iphlpapi.dll';
  ICMP_ECHO             = 8;
  ICMP_ECHOREPLY        = 0;

resourcestring
  LOG_STR_0 = '==============================================================================' + sLineBreak;
  LOG_STR_1 = 'Packet ID: %-5d TTL: %d' + sLineBreak;
  LOG_STR_2 = 'Packet size: %-5d bytes type: %s' + sLineBreak;
  LOG_STR_3 = 'Source IP      : %15s: %d' + sLineBreak;
  LOG_STR_4 = 'Destination IP : %15s: %d' + sLineBreak;
  LOG_STR_5 = 'ARP Type: %s, operation: %s' + sLineBreak;
  LOG_STR_6 = 'ICMP Type: %s' + sLineBreak;
  LOG_STR_7 = '------------------------------ Packet dump -----------------------------------' + sLineBreak;

type
  USHORT = WORD;
  ULONG = DWORD;
  time_t = Longint;


  TIPHeader = packed record
    iph_verlen:   UCHAR;
    iph_tos:      UCHAR;
    iph_length:   USHORT;
    iph_id:       USHORT;
    iph_offset:   USHORT;
    iph_ttl:      UCHAR;
    iph_protocol: UCHAR;
    iph_xsum:     USHORT;
    iph_src:      ULONG;
    iph_dest:     ULONG;
  end;
  PIPHeader = ^TIPHeader;

  TTCPHeader = packed record
    sourcePort: USHORT;
    destinationPort: USHORT;
    sequenceNumber: ULONG;
    acknowledgeNumber: ULONG;
    dataoffset: UCHAR;
    flags: UCHAR;
    windows: USHORT;
    checksum: USHORT;
    urgentPointer: USHORT;
  end;
  PTCPHeader = ^TTCPHeader;

  TUDPHeader = packed record
    sourcePort:       USHORT;
    destinationPort:  USHORT;
    len:              USHORT;
    checksum:         USHORT;
  end;
  PUDPHeader = ^TUDPHeader;

  TICMPHeader = packed record
   IcmpType      : BYTE;
   IcmpCode      : BYTE;
   IcmpChecksum  : WORD;
   IcmpId        : WORD;
   IcmpSeq       : WORD;
   IcmpTimestamp : DWORD;
  end;
  PICMPHeader = ^TICMPHeader;

  type
  PIP_ADDRESS_STRING = ^IP_ADDRESS_STRING;
  IP_ADDRESS_STRING = packed record
    acString: array [1..16] of AnsiChar;
  end;

  PIP_MASK_STRING = ^IP_MASK_STRING;
  IP_MASK_STRING = IP_ADDRESS_STRING;

  PIP_ADDR_STRING = ^IP_ADDR_STRING;
  IP_ADDR_STRING = packed record
    Next : PIP_ADDR_STRING;
    IpAddress: IP_ADDRESS_STRING;
    IpMask : IP_MASK_STRING;
    Context : DWORD;
  end;

  PIP_ADAPTER_INFO = ^IP_ADAPTER_INFO;
  IP_ADAPTER_INFO = packed record
    Next : PIP_ADAPTER_INFO;
    ComboIndex : DWORD;
    AdapterName : array [1..MAX_ADAPTER_NAME_LENGTH + 4] of AnsiChar ;
    Description : array [1..MAX_ADAPTER_DESCRIPTION_LENGTH + 4] of AnsiChar;
    AddressLength : UINT;
    Address : array [1..MAX_ADAPTER_ADDRESS_LENGTH] of Byte;
    Index : DWORD;
    dwType : UINT;
    DhcpEnabled : UINT;
    CurrentIpAddress : PIP_ADDR_STRING;
    IpAddressList : IP_ADDR_STRING;
    GatewayList : IP_ADDR_STRING;
    DhcpServer : IP_ADDR_STRING;
    HaveWins : Boolean;
    PrimaryWinsServer : IP_ADDR_STRING;
    SecondaryWinsServer : IP_ADDR_STRING;
    LeaseObtained : time_t;
    LeaseExpires : time_t;
  end;

  TSnifferThread = class(TThread)
  private
    WSA: TWSAData;
    hSocket: TSocket;
    Addr_in: sockaddr_in;
    Packet: array[0..MAX_PACKET_SIZE - 1] of Byte;
    LogData: String;
    procedure ShowPacket;
  protected
    function InitSocket: Boolean; virtual;
    procedure DeInitSocket(const ExitCode: Integer); virtual;
    procedure Execute; override;
    procedure ParcePacket(const PacketSize: Word); virtual;
  public
    Host: String;
  end;

  TForm1 = class(TForm)
    ListView1: TListView;
    Panel1: TPanel;
    ComboBox1: TComboBox;
    Label2: TLabel;
    Panel2: TPanel;
    Button1: TButton;
    Panel3: TPanel;
    GroupBox1: TGroupBox;
    CheckBox1: TCheckBox;
    CheckBox2: TCheckBox;
    CheckBox3: TCheckBox;
    CheckBox4: TCheckBox;
    CheckBox5: TCheckBox;
    CheckBox6: TCheckBox;
    PopupMenu1: TPopupMenu;
    C1: TMenuItem;
    S1: TMenuItem;
    ImageList1: TImageList;
    RichEdit1: TRichEdit;
    StatusBar1: TStatusBar;
    CheckBox7: TCheckBox;
    StatusBar2: TStatusBar;
    Memo1: TMemo;
    ComboBox2: TComboBox;
    Label1: TLabel;
    SpinEdit1: TSpinEdit;
    Label3: TLabel;
    Splitter1: TSplitter;
    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure C1Click(Sender: TObject);
    procedure S1Click(Sender: TObject);
    procedure CheckBox7Click(Sender: TObject);
    procedure ListView1Click(Sender: TObject);
    procedure ComboBox2Change(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure SpinEdit1Change(Sender: TObject);
  private
    TotalPacketCount: Integer;
    FSnifferThread: TSnifferThread;
    procedure ReadLanInterfaces;
    procedure CaptureConsoleOutput(const ACommand, AParameters: String; AMemo: TMemo);
  end;

   function GetAdaptersInfo(const pAdapterInfo: PIP_ADAPTER_INFO; const pOutBufLen: PULONG): DWORD; stdcall;
    external 'IPHLPAPI.DLL' name 'GetAdaptersInfo';

const
  IPHeaderSize = SizeOf(TIPHeader);
  ICMPHeaderSize = SizeOf(TICMPHeader);
  TCPHeaderSize = SizeOf(TTCPHeader);
  UDPHeaderSize = SizeOf(TUDPHeader);

var
  Form1: TForm1;
  PacketDump : integer = 0;
  search : integer = 0;
  find: Boolean = False;

implementation

{$R *.dfm}
procedure TForm1.CaptureConsoleOutput(const ACommand, AParameters: String; AMemo: TMemo);
 const
   CReadBuffer = 2400;
 var
   saSecurity: TSecurityAttributes;
   hRead: THandle;
   hWrite: THandle;
   suiStartup: TStartupInfo;
   piProcess: TProcessInformation;
   pBuffer: array[0..CReadBuffer] of AnsiChar;
   dRead: DWord;
   dRunning: DWord;
 begin
   saSecurity.nLength := SizeOf(TSecurityAttributes);
   saSecurity.bInheritHandle := True;
   saSecurity.lpSecurityDescriptor := nil;

   if CreatePipe(hRead, hWrite, @saSecurity, 0) then
   begin
     FillChar(suiStartup, SizeOf(TStartupInfo), #0);
     suiStartup.cb := SizeOf(TStartupInfo);
     suiStartup.hStdInput := hRead;
     suiStartup.hStdOutput := hWrite;
     suiStartup.hStdError := hWrite;
     suiStartup.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
     suiStartup.wShowWindow := SW_HIDE;

     if CreateProcess(nil, PChar(ACommand + ' ' + AParameters), @saSecurity,
       @saSecurity, True, NORMAL_PRIORITY_CLASS, nil, nil, suiStartup, piProcess)
       then
     begin
       repeat
         dRunning := WaitForSingleObject(piProcess.hProcess, 100);
         Application.ProcessMessages();
         repeat
           dRead := 0;
           ReadFile(hRead, pBuffer[0], CReadBuffer, dRead, nil);
           pBuffer[dRead] := #0;

           OemToAnsi(pBuffer, pBuffer);
           AMemo.Lines.Add(String(pBuffer));
         until (dRead < CReadBuffer);
       until (dRunning <> WAIT_TIMEOUT);
       CloseHandle(piProcess.hProcess);
       CloseHandle(piProcess.hThread);
     end;

     CloseHandle(hRead);
     CloseHandle(hWrite);
   end;
end;

procedure RE_SearchForText_AndSelect(RichEdit: TRichEdit; SearchText: string);
var StartPos, Position, RemainingLength, WordCount, TextSize, SearchSize: Integer;
begin
  if SearchText = '' then Exit;

  with RichEdit do
  begin
    Lines.BeginUpdate;

    // reset colors...
    SelStart:=0;
    SelLength:=Length(RichEdit.Text) - 1;
    SelAttributes.Color:=$000000;

    WordCount:=0;
    StartPos:=0;
    TextSize:=Length(RichEdit.Text);
    SearchSize:=Length(SearchText);
    RemainingLength:=TextSize;
    Position:=FindText(SearchText, StartPos, RemainingLength, []);

    if Position <> -1 then
    repeat
      // selects the word and changes color
      SelStart:=Position;
      SelLength:=SearchSize;
      SelAttributes.Color:=$0000FF;
      inc(WordCount);

      // changes startpos to after the current word
      StartPos:=Position + SearchSize;
      // Remaining Text to search for
      RemainingLength:=TextSize - StartPos;
      // find again...
      Position:=FindText(SearchText, StartPos, RemainingLength, []);
    until Position = -1;
    // reset selection...
    SelLength:=0;
    Lines.EndUpdate;
  end;
  //ShowMessage(SearchText + ' found ' + IntToStr(WordCount) + ' times.');
end;

procedure GetConnectionNameList(List: TStrings);
var
  pAdapterList: PIP_ADAPTER_INFO;
  dwLenAdapter: DWORD;
  ErrorCode : DWORD;
begin
  List.Clear;
  pAdapterList := nil;
  dwLenAdapter := 0;

  ErrorCode := GetAdaptersInfo(pAdapterList, @dwLenAdapter);
  If ErrorCode <> ERROR_BUFFER_OVERFLOW then
    begin
      RaiseLastOSError(ErrorCode);

      exit;
    end;

  pAdapterList := AllocMem(dwLenAdapter);
  try
    ErrorCode := GetAdaptersInfo(pAdapterList, @dwLenAdapter);

    If ErrorCode <> ERROR_SUCCESS then
      begin
        RaiseLastOSError(ErrorCode);
        exit;
      end;

    while Assigned(pAdapterList) do
      begin
        List.Add(Format('AdapterName: %s', [String(pAdapterList.AdapterName)]));
        List.Add(Format('%s', [String(pAdapterList.Description)]));
        List.Add(Format('ComboIndex: %d', [pAdapterList.ComboIndex]));
        List.Add(Format('AddressLength: %d', [pAdapterList.AddressLength]));
        List.Add(Format('Address: %d', [UInt64(pAdapterList.Address)]));
        List.Add(Format('Index: %d', [pAdapterList.Index]));
        List.Add(Format('dwType: %d', [pAdapterList.dwType]));
        List.Add(Format('DhcpEnabled: %d', [pAdapterList.DhcpEnabled]));
        List.Add(Format('IpAddressList.IpAddress: %s', [String(pAdapterList.IpAddressList.IpAddress.acString)]));
        List.Add(Format('IpAddressList.IpMask: %s', [String(pAdapterList.IpAddressList.IpMask.acString)]));
        List.Add(Format('IpAddressList.Context: %d', [pAdapterList.IpAddressList.Context]));
        List.Add(Format('GatewayList.IpAddress: %s', [String(pAdapterList.GatewayList.IpAddress.acString)]));
        List.Add(Format('GatewayList.IpMask: %s', [String(pAdapterList.GatewayList.IpMask.acString)]));
        List.Add(Format('GatewayList.Context: %d', [pAdapterList.GatewayList.Context]));
        List.Add(Format('DhcpServer.IpAddress: %s', [String(pAdapterList.DhcpServer.IpAddress.acString)]));
        List.Add(Format('DhcpServer.IpMask: %s', [String(pAdapterList.DhcpServer.IpMask.acString)]));
        List.Add(Format('DhcpServer.Context: %d', [pAdapterList.DhcpServer.Context]));
        List.Add(Format('IpAddressList.HaveWins: %d', [Integer(pAdapterList.HaveWins)]));
        List.Add(Format('PrimaryWinsServer.IpAddress: %s', [String(pAdapterList.PrimaryWinsServer.IpAddress.acString)]));
        List.Add(Format('PrimaryWinsServer.IpMask: %s', [String(pAdapterList.PrimaryWinsServer.IpMask.acString)]));
        List.Add(Format('PrimaryWinsServer.Context: %d', [pAdapterList.PrimaryWinsServer.Context]));
        List.Add(Format('SecondaryWinsServer.IpAddress: %s', [String(pAdapterList.SecondaryWinsServer.IpAddress.acString)]));
        List.Add(Format('SecondaryWinsServer.IpMask: %s', [String(pAdapterList.SecondaryWinsServer.IpMask.acString)]));
        List.Add(Format('SecondaryWinsServer.Context: %d', [pAdapterList.SecondaryWinsServer.Context]));
        pAdapterList := pAdapterList.Next;
      end;
   finally
     FreeMem(pAdapterList);
   end;
end;

function TSnifferThread.InitSocket: Boolean;
var
  PromiscuousMode: Integer;
begin
{$R-}
  Result := WSAStartup(WSA_VER, WSA) = NOERROR;
  if not Result then
  begin
    LogData := 'Error: ' + SysErrorMessage(WSAGetLastError);
    Synchronize(ShowPacket);
    Exit;
  end;
  hSocket := socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  if hSocket = INVALID_SOCKET then
  begin
    DeInitSocket(WSAGetLastError);
    Exit;
  end;

  FillChar(Addr_in, SizeOf(sockaddr_in), 0);
  Addr_in.sin_family:= AF_INET;
  Addr_in.sin_addr.s_addr := inet_addr(PAnsiChar(AnsiString(Host)));

  if bind(hSocket, Addr_in, SizeOf(sockaddr_in)) <> 0 then
  begin
    DeInitSocket(WSAGetLastError);
    Exit;
  end;
  PromiscuousMode := 1;
  if ioctlsocket(hSocket, SIO_RCVALL, PromiscuousMode) <> 0 then
  begin
    DeInitSocket(WSAGetLastError);
    Exit;
  end;
  Result := True;
  {$R+}
end;

procedure TSnifferThread.DeInitSocket(const ExitCode: Integer);
begin
  if ExitCode <> 0 then
  begin
    LogData := 'Error: ' + SysErrorMessage(ExitCode);
    Synchronize(ShowPacket);
  end;

  if hSocket <> INVALID_SOCKET then closesocket(hSocket);
  WSACleanup;
end;

procedure TSnifferThread.Execute;
var
  PacketSize: Integer;
begin
  if InitSocket then
  try
    while not Terminated do
    begin
      PacketSize := recv(hSocket, Packet, MAX_PACKET_SIZE, 0);
      if PacketSize > SizeOf(TIPHeader) then ParcePacket(PacketSize);

      Form1.StatusBar1.Panels[1].Text := IntToStr(Form1.ListView1.Items.Count);
    Application.ProcessMessages;
    end;
  finally
    DeInitSocket(NO_ERROR);

  end;

end;

procedure TSnifferThread.ParcePacket(const PacketSize: Word);
var
  IPHeader: TIPHeader;
  ICMPHeader: TICMPHeader;
  TCPHeader: TTCPHeader;
  UDPHeader: TUDPHeader;
  SrcPort, DestPort: Word;
  I, Octets, PartOctets: Integer;
  PacketType, DumpData, ExtendedInfo: String;
  Addr, A, B: TInAddr;

  item : TListItem;
begin
{$R-}
  Inc(Form1.TotalPacketCount);
  Move(Packet[0], IPHeader, IPHeaderSize);
  LogData := LOG_STR_0 + Format(LOG_STR_1, [Form1.TotalPacketCount, IPHeader.iph_ttl]);
  SrcPort := 0;
  DestPort := 0;
  ExtendedInfo := '';

  item := Form1.ListView1.Items.Add;
  item.ImageIndex := 2;

  case IPHeader.iph_protocol of

    IPPROTO_ICMP: // ICMP
    begin
      if Form1.CheckBox3.Checked = true then begin
      item.ImageIndex := 6;
      PacketType := 'ICMP';
      Move(Packet[IPHeaderSize], ICMPHeader, ICMPHeaderSize);
      case ICMPHeader.IcmpCode of
        ICMP_ECHO: ExtendedInfo := Format(LOG_STR_6, ['Echo']);
        ICMP_ECHOREPLY: ExtendedInfo := Format(LOG_STR_6, ['Echo reply']);
      else
        ExtendedInfo := Format(LOG_STR_6, ['Unknown']);
      end;
      end;
    end;

    IPPROTO_TCP: // TCP
    begin
      if Form1.CheckBox1.Checked = true then begin

      item.ImageIndex := 0;
      PacketType := 'TCP';
      Move(Packet[IPHeaderSize], TCPHeader, TCPHeaderSize);
      SrcPort := TCPHeader.sourcePort;
      DestPort := TCPHeader.destinationPort;
      end;
    end;

    IPPROTO_UDP: // UDP
    begin
      if Form1.CheckBox2.Checked = true then begin
      item.ImageIndex := 1;
      PacketType := 'UDP';
      Move(Packet[IPHeaderSize], UDPHeader, UDPHeaderSize);
      SrcPort := UDPHeader.sourcePort;
      DestPort := UDPHeader.destinationPort;
      end;
    end;

    IPPROTO_IGMP: // IGMP
    begin
      if Form1.CheckBox4.Checked = true then begin
      item.ImageIndex := 3;
      PacketType := 'IGMP';
      Move(Packet[IPHeaderSize], UDPHeader, UDPHeaderSize);
      SrcPort := UDPHeader.sourcePort;
      DestPort := UDPHeader.destinationPort;
      end;
    end;

    IPPROTO_GGP: // GGP
    begin
      if Form1.CheckBox5.Checked = true then begin
      item.ImageIndex := 4;
      PacketType := 'GGP';
      Move(Packet[IPHeaderSize], UDPHeader, UDPHeaderSize);
      SrcPort := UDPHeader.sourcePort;
      DestPort := UDPHeader.destinationPort;
      end;
    end;

    IPPROTO_PUP: // PUP
    begin
      if Form1.CheckBox6.Checked = true then begin
      item.ImageIndex := 4;
      PacketType := 'PUP';
      Move(Packet[IPHeaderSize], UDPHeader, UDPHeaderSize);
      SrcPort := UDPHeader.sourcePort;
      DestPort := UDPHeader.destinationPort;
      end;
    end;


  else
    PacketType := 'Unsupported (0x' + IntToHex(IPHeader.iph_protocol, 2) + ')';
  end;

  PacketDump := PacketDump + 1;
  Form1.Panel3.Caption := 'Packet Dump Count : ' + IntToStr(PacketDump);
  LogData := 'Dump Count : ' + IntToStr(PacketDump) + ' ' +
             LogData + Format(LOG_STR_2, [PacketSize, PacketType]);

  if ExtendedInfo <> '' then
    LogData := LogData + ExtendedInfo;
    Addr.S_addr := IPHeader.iph_src;
    LogData := LogData + Format(LOG_STR_3, [inet_ntoa(Addr), SrcPort]);

  //
    item.Caption :=  IntToStr(Form1.ListView1.Items.Count) + '. ' +
                            Format(LOG_STR_3, [inet_ntoa(Addr), SrcPort]);

    Addr.S_addr := IPHeader.iph_dest;
    LogData := LogData + Format(LOG_STR_4, [inet_ntoa(Addr), DestPort]) + LOG_STR_7;

  //
  if (Form1.CheckBox1.Checked = false) and (Form1.CheckBox2.Checked = false) and
     (Form1.CheckBox3.Checked = false) and (Form1.CheckBox4.Checked = false) and
     (Form1.CheckBox5.Checked = false) and (Form1.CheckBox6.Checked = false)
     then
     begin
      item.ImageIndex := 2;
      item.SubItems.Add(Format(LOG_STR_4, [inet_ntoa(Addr), DestPort]) + 'Network (UDP)');
      item.SubItems.Add(Format(LOG_STR_2, [PacketSize, PacketType]));
      item.SubItems.Add(Format(LOG_STR_1, [Form1.TotalPacketCount, IPHeader.iph_ttl]));
     end else begin
      item.SubItems.Add(Format(LOG_STR_4, [inet_ntoa(Addr), DestPort]));
      item.SubItems.Add(Format(LOG_STR_2, [PacketSize, PacketType]));
      item.SubItems.Add(Format(LOG_STR_1, [Form1.TotalPacketCount, IPHeader.iph_ttl]));
  end;

  I := 0;
  Octets := 0;
  PartOctets := 0;
  while I < PacketSize do
  begin
    case PartOctets of
      0: LogData := LogData + Format('%.6d ', [Octets]);
      9: LogData := LogData + '| ';
      18:
      begin
        Inc(Octets, 10);
        PartOctets := -1;
        LogData := LogData + '    ' + DumpData + sLineBreak;
        DumpData := '';
      end;
    else
      begin
        LogData := LogData + Format('%s ', [IntToHex(Packet[I], 2)]);
        if Packet[I] in [$19..$7F] then
          DumpData := DumpData + Chr(Packet[I])
        else
          DumpData := DumpData + '.';
        Inc(I);
      end;
    end;
    Inc(PartOctets);
  end;
  if PartOctets <> 0 then
  begin
    PartOctets := (16 - Length(DumpData)) * 3;
    if PartOctets >= 24 then Inc(PartOctets, 2);
    Inc(PartOctets, 4);
    LogData := LogData + StringOfChar(' ', PartOctets) +
      DumpData + sLineBreak + sLineBreak
  end
  else
    LogData := LogData + sLineBreak + sLineBreak;
  Synchronize(ShowPacket);
  With Form1.ListView1 Do begin
  If Items.Count > 0 Then
    Items [Items.Count-1].MakeVisible (True);
  end;
{$R+}
end;

procedure TSnifferThread.ShowPacket;
begin
 Form1.RichEdit1.Lines.BeginUpdate;
 Form1.RichEdit1.Text:= Form1.RichEdit1.Text+sLineBreak+LogData;
 SendMessage(Form1.RichEdit1.Handle, WM_VSCROLL, SB_BOTTOM, 0);
 Form1.RichEdit1.Lines.EndUpdate;
{  frmMain.memReport.Lines.BeginUpdate;
  frmMain.memReport.Text :=
    frmMain.memReport.Text + sLineBreak + LogData;
  SendMessage(frmMain.memReport.Handle, WM_VSCROLL, SB_BOTTOM, 0);
  frmMain.memReport.Lines.EndUpdate;   }
end;

procedure TForm1.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  //FSnifferThread.Terminate;
  FSnifferThread := nil;
  Application.Terminate;
end;

procedure TForm1.FormCreate(Sender: TObject);
resourcestring
    cTxtIP = '%d.%d.%d.%d';

var
    rSockVer : WordRec; aWSAData : TWSAData;
    szHostName : array[0..255] of Char; pHE : PHostEnt; sIP : String;
begin
  DoubleBuffered := true;
  TotalPacketCount := 0;
  RichEdit1.MaxLength := $7FFFFFF0;
  GetConnectionNameList(ComboBox1.Items);
  ComboBox1.ItemIndex := 1;

  rSockVer.Hi := 1;
  rSockVer.Lo := 1;
  WSAStartup(Word(rSockVer), aWSAData );
   try
     FillChar(szHostName, SizeOf(szHostName), #0);
     GetHostName(@szHostName, SizeOf(szHostName));
     pHE := GetHostByName(@szHostName);
     if Assigned(pHE) then with pHE^ do
      sIP := Format(cTxtIP,[Byte(h_addr^[0]), Byte(h_addr^[1]),
                    Byte(h_addr^[2]), Byte(h_addr^[3])]);
   finally
   WSACleanup;
   StatusBar1.Panels[3].Text := sIP;
  end;

  CaptureConsoleOutput('cmd /c', 'curl -4 icanhazip.com', Memo1);
  StatusBar1.Panels[5].Text := Memo1.Lines[4];
end;

procedure TForm1.ReadLanInterfaces;
//var
  //InterfaceInfo,
  //TmpPointer: PIP_ADAPTER_INFO;
  //IP: PIP_ADDR_STRING;
  //Len: ULONG;
begin
{  This Section is for older Delphi Versions
  if GetAdaptersInfo(nil, Len) = ERROR_BUFFER_OVERFLOW then
  begin
    GetMem(InterfaceInfo, Len);
    try
      if GetAdaptersInfo(InterfaceInfo, Len) = ERROR_SUCCESS then
      begin
        TmpPointer := InterfaceInfo;
        repeat
          IP := @TmpPointer.IpAddressList;
          repeat
            ComboBox1.Items.Add(Format('%s - [%s]',
              [IP^.IpAddress.S, TmpPointer.Description]));
             IP := IP.Next;
          until IP = nil;
          TmpPointer := TmpPointer.Next;
        until TmpPointer = nil;
      end;
    finally
      FreeMem(InterfaceInfo);
    end;
  end;
  if ComboBox1.Items.Count = 0 then
  begin
    RichEdit1.Text := 'No Interface found.' + sLineBreak +
      'Sniffer stopped.';
    Button1.Enabled := False;
    Exit;
  end
  else
    ComboBox1.ItemIndex := 0;
    }
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  if FSnifferThread <> nil then
  begin
    FSnifferThread.Terminate;
    FSnifferThread := nil;
    Button1.Caption := 'Start';
    RichEdit1.Enabled := true;
    ComboBox1.Enabled := true;
    ComboBox2.Enabled := true;
    C1.Enabled := true;
    S1.Enabled := true;

  end
  else
  begin
    FSnifferThread := TSnifferThread.Create(True);
    FSnifferThread.Host := Copy(ComboBox1.Text, 1, Pos(' ', ComboBox1.Text));
    FSnifferThread.FreeOnTerminate := True;
    FSnifferThread.Resume;
    Button1.Caption := 'Stop';

    RichEdit1.Enabled := false;
    ComboBox1.Enabled := false;
    ComboBox2.Enabled := false;
    C1.Enabled := false;
    S1.Enabled := false;
  end;
end;

procedure TForm1.C1Click(Sender: TObject);
begin
  ListView1.Clear;
  RichEdit1.Clear;
  PacketDump := 0;
  StatusBar1.Panels[1].Text := '0';
  StatusBar2.Panels[1].Text := '';
  Application.ProcessMessages;
end;

procedure TForm1.S1Click(Sender: TObject);
var  i : Integer;
begin
     with TStringList.Create do
     try
        for i := 0 to Form1.ListView1.Items.Count-1 do
           Add(Form1.ListView1.Items[i].Caption +',' +
               Form1.ListView1.Items[i].SubItems.CommaText);
           Text := StringReplace(Text,',',#9,[rfReplaceAll]);
           try
              SaveToFile(ExtractFilePath(Application.ExeName) + 'packetDumpInfo.txt');
           except
              ShowMessage('Error TXT');
           end;
     finally
        free;
     end;
end;

procedure TForm1.SpinEdit1Change(Sender: TObject);
begin
  RichEdit1.Font.Size := SpinEdit1.Value;
end;

procedure TForm1.CheckBox7Click(Sender: TObject);
begin
  if CheckBox7.Checked = true then begin
  SetWindowPos(Handle, HWND_TOPMOST, Left,Top, Width,Height,
             SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
  end else begin
  SetWindowPos(Handle, HWND_NOTOPMOST, Left,Top, Width,Height,
             SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
  end;
end;

procedure TForm1.ComboBox2Change(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  try
    case ComboBox2.ItemIndex of
    0 : begin
          Memo1.Clear;
          CaptureConsoleOutput('cmd /c', 'curl -4 icanhazip.com', Memo1);
          Sleep(50);
          StatusBar1.Panels[5].Text := Memo1.Lines[4];
        end;
    1 : begin
          Memo1.Clear;
          CaptureConsoleOutput('cmd /c', 'curl -6 icanhazip.com', Memo1);
          Sleep(50);
          StatusBar1.Panels[5].Text := Memo1.Lines[4];
        end;
    end;
  except
    on E: Exception do
      begin
      ShowMessage('Connection Error' + E.Message);
      StatusBar1.Panels[3].Text := 'n/a';
      StatusBar1.Panels[3].Text := 'n/a';
      end;
  end;


  Screen.Cursor := crDefault;
  StatusBar1.SetFocus;
end;

procedure TForm1.ListView1Click(Sender: TObject);
begin
  if ListView1.ItemIndex <= -1 then Exit;
  if Button1.Caption = 'Stop' then Exit;

  Screen.Cursor := crHourGlass;
  try
    RE_SearchForText_AndSelect(RichEdit1,
    'Dump Count : ' + IntToStr(ListView1.Selected.Index+1) + ' ==============================================================================');

    RichEdit1.SetFocus;
    RichEdit1.perform( EM_SCROLLCARET, 0, 0 );
    StatusBar2.Panels[1].Text := ListView1.Selected.SubItems.Text;
  except
    on E: Exception do begin
      ShowMessage('Cant locate Packet dump, ' + E.Message);
      Screen.Cursor := crDefault;
      end;
  end;
  Screen.Cursor := crDefault;
end;

end.
