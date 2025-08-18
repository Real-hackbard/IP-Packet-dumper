unit uMain;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, WinSock, ComCtrls, XPMan, ExtCtrls, Menus, ImgList;

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

  IP_ADDRESS_STRING = record
    S: array [0..15] of Char;
  end;
  IP_MASK_STRING = IP_ADDRESS_STRING;
  PIP_MASK_STRING = ^IP_MASK_STRING;

  PIP_ADDR_STRING = ^IP_ADDR_STRING;
  IP_ADDR_STRING = record
    Next: PIP_ADDR_STRING;
    IpAddress: IP_ADDRESS_STRING;
    IpMask: IP_MASK_STRING;
    Context: DWORD;
  end;

  PIP_ADAPTER_INFO = ^IP_ADAPTER_INFO;
  IP_ADAPTER_INFO = record
    Next: PIP_ADAPTER_INFO;
    ComboIndex: DWORD;
    AdapterName: array [0..MAX_ADAPTER_NAME_LENGTH + 3] of Char;
    Description: array [0..MAX_ADAPTER_DESCRIPTION_LENGTH + 3] of Char;
    AddressLength: UINT;
    Address: array [0..MAX_ADAPTER_ADDRESS_LENGTH - 1] of BYTE;
    Index: DWORD;
    Type_: UINT;
    DhcpEnabled: UINT;
    CurrentIpAddress: PIP_ADDR_STRING;
    IpAddressList: IP_ADDR_STRING;
    GatewayList: IP_ADDR_STRING;
    DhcpServer: IP_ADDR_STRING;
    HaveWins: BOOL;
    PrimaryWinsServer: IP_ADDR_STRING;
    SecondaryWinsServer: IP_ADDR_STRING;
    LeaseObtained: time_t;
    LeaseExpires: time_t;
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
    Splitter1: TSplitter;
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
    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure C1Click(Sender: TObject);
    procedure S1Click(Sender: TObject);
    procedure ListView1Change(Sender: TObject; Item: TListItem;
      Change: TItemChange);
    procedure CheckBox7Click(Sender: TObject);
    procedure ListView1Click(Sender: TObject);
  private
    TotalPacketCount: Integer;
    FSnifferThread: TSnifferThread;
    procedure ReadLanInterfaces;
  end;

  function GetAdaptersInfo(pAdapterInfo: PIP_ADAPTER_INFO;
    var pOutBufLen: ULONG): DWORD; stdcall; external IPHelper;

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

function TSnifferThread.InitSocket: Boolean;
var
  PromiscuousMode: Integer;
begin
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
  Addr_in.sin_addr.s_addr := inet_addr(PChar(Host));
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
  LogData := 'Dump Count : ' + IntToStr(PacketDump) + ' ' + LogData + Format(LOG_STR_2, [PacketSize, PacketType]);

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

procedure TForm1.FormCreate(Sender: TObject);
begin
  TotalPacketCount := 0;
  RichEdit1.MaxLength := $7FFFFFF0;
  ReadLanInterfaces;
end;

procedure TForm1.ReadLanInterfaces;
var
  InterfaceInfo,
  TmpPointer: PIP_ADAPTER_INFO;
  IP: PIP_ADDR_STRING;
  Len: ULONG;
begin
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
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  if FSnifferThread <> nil then
  begin
    FSnifferThread.Terminate;
    FSnifferThread := nil;
    Button1.Caption := 'Start';
  end
  else
  begin
    FSnifferThread := TSnifferThread.Create(True);
    FSnifferThread.Host := Copy(ComboBox1.Text, 1, Pos(' ', ComboBox1.Text));
    FSnifferThread.FreeOnTerminate := True;
    FSnifferThread.Resume;
    Button1.Caption := 'Stop';
  end;
end;

procedure TForm1.C1Click(Sender: TObject);
begin
  try
    FSnifferThread.Terminate;
    FSnifferThread := nil;
    Sleep(500);
    FSnifferThread := TSnifferThread.Create(True);
    FSnifferThread.Resume;
  except
  end;

  ListView1.Clear;
  RichEdit1.Clear;
  PacketDump := 0;

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

procedure TForm1.ListView1Change(Sender: TObject; Item: TListItem;
  Change: TItemChange);
begin
  StatusBar1.Panels[1].Text := IntToStr(ListView1.Items.Count);
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

procedure TForm1.ListView1Click(Sender: TObject);
begin
  StatusBar1.Panels[3].Text := ListView1.Selected.SubItems.Text;
end;

end.
