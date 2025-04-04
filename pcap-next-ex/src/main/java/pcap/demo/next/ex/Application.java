package pcap.demo.next.ex;

import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

public class Application {

  private static final Logger LOG = LoggerFactory.getLogger(Application.class);

  public static void main(String[] args) {
    try {
      final var service = Service.Creator.create("PcapService");
      final var source = service.interfaces();
      LOG.info("Source: {}", source.name());
      try (final var pcap = service.live(source, new DefaultLiveOptions())) {
        if (pcap.datalink() == Ethernet.TYPE) {
          final var packet = pcap.allocate(PacketBuffer.class);
          final var header = pcap.allocate(PacketHeader.class);
          for (var i = 0; i < 10; i++) {
            try {
              pcap.nextEx(header, packet);
              // Only if needed, and don't forget to free the copied buffer after no longer in use
              // https://github.com/ardikars/pcap/issues/327
              var buffer = packet.copy();
              buffer.setIndex(packet.readerIndex(), packet.writerIndex());
              final var ethernet = buffer.cast(Ethernet.class);
              LOG.info("Header: {}", header);
              LOG.info("Buffer: {}", buffer);
              LOG.info("Packets");
              LOG.info(ethernet);
              switch (ethernet.type()) {
                case Ip4.TYPE -> {
                  final var ip4 = buffer.readerIndex(ethernet.size()).cast(Ip4.class);
                  LOG.info(ip4);
                  switch (ip4.protocol()) {
                    case Tcp.TYPE -> {
                      final var tcp = buffer.readerIndex(ethernet.size() + ip4.size()).cast(Tcp.class);
                      LOG.info(tcp);
                    }
                    case Udp.TYPE -> {
                      final var udp = buffer.readerIndex(ethernet.size() + ip4.size()).cast(Udp.class);
                      LOG.info(udp);
                    }
                  }
                }
                case Ip6.TYPE -> {
                  final var ip6 = buffer.readerIndex(ethernet.size()).cast(Ip6.class);
                  LOG.info(ip6);
                  switch (ip6.nextHeader()) {
                    case Tcp.TYPE -> {
                      final var tcp = buffer.readerIndex(ethernet.size() + ip6.size()).cast(Tcp.class);
                      LOG.info(tcp);
                    }
                    case Udp.TYPE -> {
                      final var udp = buffer.readerIndex(ethernet.size() + ip6.size()).cast(Udp.class);
                      LOG.info(udp);
                    }
                  }
                }
              }
              buffer.release(); // free the buffer
            } catch (BreakException | TimeoutException e) {
              LOG.error(e);
            }
          }
        }
      } catch (RadioFrequencyModeNotSupportedException
          | NoSuchDeviceException
          | ActivatedException
          | InterfaceNotSupportTimestampTypeException
          | PromiscuousModePermissionDeniedException
          | InterfaceNotUpException
          | PermissionDeniedException
          | TimestampPrecisionNotSupportedException e) {
        LOG.error(e);
      }
    } catch (ErrorException e) {
      LOG.error(e);
    }
  }
}
