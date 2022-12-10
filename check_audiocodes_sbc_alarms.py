#!/usr/bin/env python
###
# Version 1.0 - ali/29.11.2022
# Monitoring AudioCodes SBC alarm state
##
# Version 1.1 - ali/10.12.2022
# Cleanup
###
# Nagios Exit-Codes:
# 0 = OK
# 1 = WARNING
# 2 = CRITICAL
# 3 = UNKNOWN
###
# Name:    acActiveAlarmTextualDescription
# OID:     1.3.6.1.4.1.5003.11.1.1.1.1.6
# MIB:     AcAlarm
# Type:    OctetString
# Descr:   Text that describes the alarm condition.
# Example: Certificate expiry: The certificate of TLS context 0 will expire in 11 days.
###
# Name:    acActiveAlarmSeverity
# OID:     1.3.6.1.4.1.5003.11.1.1.1.1.8
# MIB:     AcAlarm
# Type:    Integer
# Syntax:  AcAlarmSeverity {cleared(0),indeterminate(1),warning(2),minor(3),major(4),critical(5)}
# Descr:   The severity of the alarm.
# Example: warning (2)
###
# Name:    acActiveAlarmProbableCause
# OID:     1.3.6.1.4.1.5003.11.1.1.1.1.10
# MIB:     AcAlarm
# Type:    Integer
# Syntax:  AcAlarmProbableCause {other(0),adapterError(1),applicationSubsystemFailure(2),bandwidthReduced(3),callEstablishmentError(4),communicationsProtocolError(5),communicationsSubsystemFailure(6),configurationOrCustomizationError(7),congestion(8),corruptData(9),cpuCyclesLimitExceeded(10),dataSetOrModemError(11),degradedSignal(12),dteDceInterfaceError(13),enclosureDoorOpen(14),equipmentMalfunction(15),excessiveVibration(16),fileError(17),fireDetected(18),floodDetected(19),framingError(20),heatingVentCoolingSystemProblem(21),humidityUnacceptable(22),inputOutputDeviceError(23),inputDeviceError(24),lanError(25),leakDetected(26),localNodeTransmissionError(27),lossOfFrame(28),lossOfSignal(29),materialSupplyExhausted(30),multiplexerProblem(31),outOfMemory(32),ouputDeviceError(33),performanceDegraded(34),powerProblem(35),pressureUnacceptable(36),processorProblem(37),pumpFailure(38),queueSizeExceeded(39),receiveFailure(40),receiverFailure(41),remoteNodeTransmissionError(42),resourceAtOrNearingCapacity(43),responseTimeExecessive(44),retransmissionRateExcessive(45),softwareError(46),softwareProgramAbnormallyTerminated(47),softwareProgramError(48),storageCapacityProblem(49),temperatureUnacceptable(50),thresholdCrossed(51),timingProblem(52),toxicLeakDetected(53),transmitFailure(54),transmitterFailure(55),underlyingResourceUnavailable(56),versionMismatch(57),authenticationFailure(58),breachOfConfidentiality(59),cableTamper(60),delayedInformation(61),denialOfService(62),duplicateInformation(63),informationMissing(64),informationModificationDetected(65),informationOutOfSequence(66),intrusionDetection(67),keyExpired(68),nonRepudiationFailure(69),outOfHoursActivity(70),outOfService(71),proceduralError(72),unauthorizedAccessAttempt(73),unexpectedInformation(74)}
# Descr:   The probable cause of the alarm.
# Example: communicationsSubsystemFailure (6)
###


import sys
import re
import subprocess


def main(switchhostname, snmpcommunity):

    regex_descr = re.compile(r'3\.6\.1\.4\.1\.5003\.11\.1\.1\.1\.1\.6\.\d+\s=\sSTRING:\s"(.+)"')
    regex_severity = re.compile(r'3\.6\.1\.4\.1\.5003\.11\.1\.1\.1\.1\.8\.\d+\s=\sINTEGER:\s(\d)')
    regex_prob_cause = re.compile(r'3\.6\.1\.4\.1\.5003\.11\.1\.1\.1\.1\.10\.\d+\s=\sINTEGER:\s(\d+)')
    code_warning = 0
    code_critical = 0
    code_unknown = 0
    alarm_list = []
    alarm_descr = []
    alarm_severity = []
    alarm_prob_cause = []
    att_severity = {0:'cleared',1:'indeterminate',2:'warning',3:'minor',4:'major',5:'critical'}
    att_prob_cause = {0:'Other',1:'Adapter error',2:'Application subsystem failure',3:'Bandwidth reduced',4:'Call establishment error',5:'Communications protocol error',6:'Communications subsystem failure',7:'Configuration or customization error',8:'Congestion',9:'Corrupt data',10:'CPU cycles limit exceeded',11:'Data set or modem error',12:'Degraded signal',13:'DTE DCE interface error',14:'Enclosure door open',15:'Equipment malfunction',16:'Excessive vibration',17:'File error',18:'Fire detected',19:'Flood detected',20:'Framing error',21:'Heating vent cooling system problem',22:'Humidity unacceptable',23:'Input output device error',24:'Input device error',25:'LAN error',26:'Leak detected',27:'Local node transmission error',28:'Loss of frame',29:'Loss of signal',30:'Material supply exhausted',31:'Multiplexer problem',32:'Out of memory',33:'Ouput device error',34:'Performance degraded',35:'Power problem',36:'Pressure unacceptable',37:'Processor problem',38:'Pump failure',39:'Queue size exceeded',40:'Receive failure',41:'Receiver failure',42:'Remote node transmission error',43:'Resource at or nearing capacity',44:'Response time execessive',45:'Retransmission rate excessive',46:'Software error',47:'Software program abnormally terminated',48:'Software program error',49:'Storage capacity problem',50:'Temperature unacceptable',51:'Threshold crossed',52:'Timing problem',53:'Toxic leak detected',54:'Transmit failure',55:'Transmitter failure',56:'Underlying resource unavailable',57:'Version mismatch',58:'Authentication failure',59:'Breach of confidentiality',60:'Cable tamper',61:'Delayed information',62:'Denial of service',63:'Duplicate information',64:'Information missing',65:'Information modification detected',66:'Information out of sequence',67:'Intrusion detection',68:'Key expired',69:'Non-repudiation failure',70:'Out of hours activity',71:'Out of service',72:'Procedural error',73:'Unauthorized access attempt',74:'Unexpected information'}

#   gather facts
    p = subprocess.Popen("snmpwalk " + switchhostname + " -v 2c -c " + snmpcommunity + " 1.3.6.1.4.1.5003.11.1.1.1.1",shell=True,stdout=subprocess.PIPE)
#   read output from subprocess and decode bytes to string as utf-8
    alarm_proc = p.stdout.read().decode('utf-8')

    try:

#       split new-lines
        alarm_list = alarm_proc.splitlines()

#       extract description, severity and probable cause
        for line in alarm_list:
            match_descr = regex_descr.search(line)
            match_severity = regex_severity.search(line)
            match_prob_cause = regex_prob_cause.search(line)
            if match_descr: alarm_descr.append(match_descr.group(1))
            elif match_severity: alarm_severity.append(int(match_severity.group(1)))
            elif match_prob_cause: alarm_prob_cause.append(int(match_prob_cause.group(1)))

#       get severity and set codes
        i = 0
        while i < len(alarm_descr):
            if alarm_severity[i] in [1,2,3]: code_warning += 1
            elif alarm_severity[i] in [4,5]: code_critical += 1
            elif alarm_severity[i] not in att_severity: code_unknown += 1
            i += 1

#       print output and generate performance-data
        if code_critical: print("CRITICAL - Alarm present | alarm_state=2;1;2;0;3")
        elif code_warning: print("WARNING - Alarm present | alarm_state=1;1;2;0;3")
        elif code_unknown: print("UNKNOWN - Alarm present | alarm_state=3;1;2;0;3")
        else: print("OK - No Alarms present | alarm_state= 0;1;2;0;3")

        if code_critical or code_warning:
            i = 0
            while i < len(alarm_descr):
                print("Alarm: %s\nSeverity: %s\nProbable cause: %s\n" % (alarm_descr[i],att_severity[alarm_severity[i]],att_prob_cause[alarm_prob_cause[i]]))
                i += 1

#       exit script with nagios return-code
        if code_critical: sys.exit(2)
        elif code_warning: sys.exit(1)
        elif code_unknown: sys.exit(3)
        else: sys.exit(0)

    except Exception as e:
        print("UNKNOWN - An error occured | alarm_state=3;1;2;0;3")
        print("%s" % e)
        sys.exit(3)


if __name__ == '__main__':

    if len(sys.argv) != 3:
        print("\n\t[*] check_audiocodes_sbc_alarms 1.1 [*]")
        print("\n\tUsage: check_audiocodes_sbc_alarms.py HOSTNAME SNMPCOMMUNITY")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
