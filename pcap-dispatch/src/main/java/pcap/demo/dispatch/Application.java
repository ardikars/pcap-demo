package pcap.demo.dispatch;

import pcap.codec.ethernet.Ethernet;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.DefaultTimeout;


public class Application {

  private static final Logger LOG = LoggerFactory.getLogger(Application.class);

  public static void main(String[] args) {
    try {
      final var service = Service.Creator.create("PcapService");
      try (final var selector = service.selector()) {
        for (final var source : service.interfaces()) {
          if ((source.flags() & Interface.PCAP_IF_UP) != 0
              && (source.flags() & Interface.PCAP_IF_RUNNING) != 0
              && (source.flags() & Interface.PCAP_IF_CONNECTION_STATUS_CONNECTED) != 0) {
            final var pcap = service.live(source, new DefaultLiveOptions());
            if (pcap.datalink() == Ethernet.TYPE) {
              LOG.info("Source: {}", source.name());
              selector.register(pcap);
            } else {
              pcap.close();
            }
          }
        }
        for(int i = 0; i < 10; i++) {
          selector.select(Application::accept, new DefaultTimeout(1000000L, Timeout.Precision.MICRO));
        }
      } catch (Exception e) {
        LOG.error(e);
      }
    } catch (ErrorException e) {
      LOG.error(e);
    }
  }

  private static void accept(final Selection selection) {
    if (selection.isReadable()) {
      final var pcap = (Pcap) selection.selectable();
      try {
        pcap.dispatch(1, Application::gotPacket, null);
        selection.interestOperations(Selection.OPERATION_WRITE);
      } catch (BreakException | ErrorException | TimeoutException e) {
        LOG.error(e);
      }
    } else if (selection.isWritable()) {
      selection.interestOperations(Selection.OPERATION_READ);
    }
  }

  private static void gotPacket(Object args, PacketHeader header, PacketBuffer buffer) {
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
  }
}
