CREATE TABLE `sip_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timeGMT` datetime NOT NULL,
  `timeMicroSec` int(11) NOT NULL,
  `srcAddress` varchar(45) NOT NULL,
  `srcPort` int(11) NOT NULL,
  `dstAddress` varchar(45) NOT NULL,
  `dstPort` int(11) NOT NULL,
  `sipID` varchar(100) NOT NULL,
  `sipCSeq` varchar(32) DEFAULT NULL,
  `sipUserAgent` varchar(256) DEFAULT NULL,
  `sipTo` varchar(256) DEFAULT NULL,
  `sipFrom` varchar(256) DEFAULT NULL,
  `sipCommand` varchar(256) DEFAULT NULL,
  `sipData` varchar(4096) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sipID` (`sipID`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
