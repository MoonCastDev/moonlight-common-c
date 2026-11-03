#include "Limelight-internal.h"

#if defined(__APPLE__)
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <signal.h>
#endif

// MoonCast: the receive thread's once-a-second diagnostics (LiSetVideoReceiveDiagnostics)
static bool receiveDiagnostics;

void LiSetVideoReceiveDiagnostics(bool enabled) {
    receiveDiagnostics = enabled;
}

void RtpvResetUnrecoverableFrames(void);

// MoonCast: the stream's totals so far (written by the receive thread only)
static volatile uint64_t totalPackets, totalBytes, totalMissing;

void LiGetVideoReceiveTotals(uint64_t* packets, uint64_t* bytes, uint64_t* missing) {
    *packets = totalPackets;
    *bytes = totalBytes;
    *missing = totalMissing;
}

#if defined(__APPLE__)
// The system's count of UDP datagrams dropped for a full socket buffer, or -1 where it can't be read
static int64_t udpFullSocketDrops(void) {
    // struct udpstat (netinet/udp_var.h, not in the iOS SDK) starts with seven 32-bit counters, the 7th being
    // udps_fullsock
    uint32_t st[64];
    size_t len = sizeof(st);
    if (sysctlbyname("net.inet.udp.stats", st, &len, NULL, 0) != 0 || len < 7 * sizeof(uint32_t)) {
        return -1;
    }
    return st[6];
}
#endif

#define FIRST_FRAME_MAX 1500
#define FIRST_FRAME_TIMEOUT_SEC 10

#define FIRST_FRAME_PORT 47996

static RTP_VIDEO_QUEUE rtpQueue;

static SOCKET rtpSocket = INVALID_SOCKET;
static SOCKET firstFrameSocket = INVALID_SOCKET;

static PPLT_CRYPTO_CONTEXT decryptionCtx;

static PLT_THREAD udpPingThread;
static PLT_THREAD receiveThread;
static PLT_THREAD decoderThread;

static bool receivedDataFromPeer;
static uint64_t firstDataTimeMs;
static bool receivedFullFrame;

// We can't request an IDR frame until the depacketizer knows
// that a packet was lost. This timeout bounds the time that
// the RTP queue will wait for missing/reordered packets.
#define RTP_QUEUE_DELAY 10

// This is the desired number of video packets that can be
// stored in the socket's receive buffer. 2048 is chosen
// because it should be large enough for all reasonable
// frame sizes (probably 2 or 3 frames) without using too
// much kernel memory with larger packet sizes. It also
// can smooth over transient pauses in network traffic
// and subsequent packet/frame bursts that follow.
// Room for ~11 MB of video so 500-1000 Mbps streams survive brief stalls; the OS caps it at its own maximum
#define RTP_RECV_PACKETS_BUFFERED 8192

// Initialize the video stream
void initializeVideoStream(void) {
    initializeVideoDepacketizer(StreamConfig.packetSize);
    RtpvInitializeQueue(&rtpQueue);
    decryptionCtx = PltCreateCryptoContext();
    receivedDataFromPeer = false;
    firstDataTimeMs = 0;
    receivedFullFrame = false;
    totalPackets = totalBytes = totalMissing = 0;
    RtpvResetUnrecoverableFrames();
}

// Clean up the video stream
void destroyVideoStream(void) {
    PltDestroyCryptoContext(decryptionCtx);
    destroyVideoDepacketizer();
    RtpvCleanupQueue(&rtpQueue);
}

// UDP Ping proc
static void VideoPingThreadProc(void* context) {
    char legacyPingData[] = { 0x50, 0x49, 0x4E, 0x47 };
    LC_SOCKADDR saddr;

    LC_ASSERT(VideoPortNumber != 0);

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, VideoPortNumber);

    // We do not check for errors here. Socket errors will be handled
    // on the read-side in ReceiveThreadProc(). This avoids potential
    // issues related to receiving ICMP port unreachable messages due
    // to sending a packet prior to the host PC binding to that port.
    int pingCount = 0;
    while (!PltIsThreadInterrupted(&udpPingThread)) {
        if (VideoPingPayload.payload[0] != 0) {
            pingCount++;
            VideoPingPayload.sequenceNumber = BE32(pingCount);

            sendto(rtpSocket, (char*)&VideoPingPayload, sizeof(VideoPingPayload), 0, (struct sockaddr*)&saddr, AddrLen);
        }
        else {
            sendto(rtpSocket, legacyPingData, sizeof(legacyPingData), 0, (struct sockaddr*)&saddr, AddrLen);
        }

        PltSleepMsInterruptible(&udpPingThread, 500);
    }
}

// Receive thread proc
static void VideoReceiveThreadProc(void* context) {
    int err;
    int bufferSize, receiveSize, decryptedSize, minSize;
    char* buffer;
    char* encryptedBuffer;
    int queueStatus;
    bool useSelect;
    int waitingForVideoMs;
    bool encrypted;

    encrypted = !!(EncryptionFeaturesEnabled & SS_ENC_VIDEO);
    decryptedSize = StreamConfig.packetSize + MAX_RTP_HEADER_SIZE;
    minSize = sizeof(RTP_PACKET) + ((EncryptionFeaturesEnabled & SS_ENC_VIDEO) ? sizeof(ENC_VIDEO_HEADER) : 0);
    receiveSize = decryptedSize + ((EncryptionFeaturesEnabled & SS_ENC_VIDEO) ? sizeof(ENC_VIDEO_HEADER) : 0);
    bufferSize = decryptedSize + sizeof(RTPV_QUEUE_ENTRY);
    buffer = NULL;

    if (setNonFatalRecvTimeoutMs(rtpSocket, UDP_RECV_POLL_TIMEOUT_MS) < 0) {
        // SO_RCVTIMEO failed, so use select() to wait
        useSelect = true;
    }
    else {
        // SO_RCVTIMEO timeout set for recv()
        useSelect = false;
    }

    // Allocate a staging buffer to use for each received packet
    if (encrypted) {
        encryptedBuffer = (char*)malloc(receiveSize);
        if (encryptedBuffer == NULL) {
            Limelog("Video Receive: malloc() failed\n");
            ListenerCallbacks.connectionTerminated(-1);
            return;
        }
    }
    else {
        encryptedBuffer = NULL;
    }

    // MoonCast: whether this thread blocks SIGTERM (for a terminate that seems ignored), and that diagnostics are on
    {
#if defined(__APPLE__)
        sigset_t mask;
        pthread_sigmask(SIG_BLOCK, NULL, &mask);
        fprintf(stderr, "MoonCast: video receive thread: diagnostics %s, SIGTERM %s, SIGINT %s in this thread\n",
                receiveDiagnostics ? "on" : "off", sigismember(&mask, SIGTERM) ? "blocked" : "not blocked",
                sigismember(&mask, SIGINT) ? "blocked" : "not blocked");
#else
        fprintf(stderr, "MoonCast: video receive thread: diagnostics %s\n", receiveDiagnostics ? "on" : "off");
#endif
        fflush(stderr);
    }

#if defined(__APPLE__)
    // MoonCast: this thread must keep up with PyroWave's bursts (hundreds of packets a frame at hundreds of Mbps):
    // it runs at the highest QoS, like the frame thread
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif

    // MoonCast: diagnostics (LiSetVideoReceiveDiagnostics)
    uint64_t diagStartUs = PltGetMicroseconds(), diagLastRecvUs = 0, diagMaxPauseUs = 0, diagMaxWorkUs = 0;
    uint32_t diagPackets = 0, diagSeqGaps = 0, diagSeqBack = 0, diagLostAtStart = LiGetVideoUnrecoverableFrames();
    uint64_t diagBytes = 0;
    int diagMaxQueued = 0, diagMaxPending = 0;
    uint16_t diagLastSeq = 0;
    bool diagHaveSeq = false;
    uint32_t skippedSinceSeq = 0;
#if defined(__APPLE__)
    int64_t diagDropsAtStart = receiveDiagnostics ? udpFullSocketDrops() : -1;
#else
    int64_t diagDropsAtStart = -1;
#endif

    waitingForVideoMs = 0;
    while (!PltIsThreadInterrupted(&receiveThread)) {
        PRTP_PACKET packet;
        uint64_t diagRecvUs = 0;

        if (receiveDiagnostics) {
            uint64_t nowUs = PltGetMicroseconds();
            if (nowUs - diagStartUs >= 1000000) {
                double secs = (nowUs - diagStartUs) / 1000000.0;
                int64_t drops = -1;
#if defined(__APPLE__)
                int64_t d = udpFullSocketDrops();
                if (d >= 0 && diagDropsAtStart >= 0) drops = d - diagDropsAtStart;
                diagDropsAtStart = d;
#endif
                uint32_t lost = LiGetVideoUnrecoverableFrames();
                fprintf(stderr, "MoonCast: video receive %.2f s: %u packets, %.1f Mbps, %u missing by RTP sequence (%u out of order), "
                        "%lld dropped by the system for a full socket buffer, longest pause %.1f ms, longest packet work %.2f ms, "
                        "most waiting in the socket %d KB, %u frames unrecoverable, decode queue up to %d\n",
                        secs, diagPackets, diagBytes * 8 / secs / 1000000.0, diagSeqGaps, diagSeqBack, (long long)drops,
                        diagMaxPauseUs / 1000.0, diagMaxWorkUs / 1000.0, diagMaxQueued / 1024, lost - diagLostAtStart, diagMaxPending);
                fflush(stderr);
                diagStartUs = nowUs;
                diagPackets = diagSeqGaps = diagSeqBack = 0;
                diagBytes = 0;
                diagMaxPauseUs = diagMaxWorkUs = 0;
                diagMaxQueued = diagMaxPending = 0;
                diagLostAtStart = lost;
            }
        }

        if (buffer == NULL) {
            buffer = (char*)malloc(bufferSize);
            if (buffer == NULL) {
                Limelog("Video Receive: malloc() failed\n");
                ListenerCallbacks.connectionTerminated(-1);
                break;
            }
        }

        err = recvUdpSocket(rtpSocket,
                            encrypted ? encryptedBuffer : buffer,
                            receiveSize,
                            useSelect);
        if (err < 0) {
            Limelog("Video Receive: recvUdpSocket() failed: %d\n", (int)LastSocketError());
            ListenerCallbacks.connectionTerminated(LastSocketFail());
            break;
        }
        else if  (err == 0) {
            if (!receivedDataFromPeer) {
                // If we wait many seconds without ever receiving a video packet,
                // assume something is broken and terminate the connection.
                waitingForVideoMs += UDP_RECV_POLL_TIMEOUT_MS;
                if (waitingForVideoMs >= FIRST_FRAME_TIMEOUT_SEC * 1000) {
                    Limelog("Terminating connection due to lack of video traffic\n");
                    ListenerCallbacks.connectionTerminated(ML_ERROR_NO_VIDEO_TRAFFIC);
                    break;
                }
            }

            // Receive timed out; try again
            continue;
        }

        totalPackets++;
        totalBytes += err;

        if (receiveDiagnostics) {
            diagRecvUs = PltGetMicroseconds();
            if (diagLastRecvUs != 0 && diagRecvUs - diagLastRecvUs > diagMaxPauseUs) {
                diagMaxPauseUs = diagRecvUs - diagLastRecvUs;
            }
            diagLastRecvUs = diagRecvUs;
            diagPackets++;
            diagBytes += err;
#if defined(__APPLE__)
            // what's still waiting in the socket, every 64th packet
            if ((diagPackets & 63) == 0) {
                int queued = 0;
                if (ioctl(rtpSocket, FIONREAD, &queued) == 0 && queued > diagMaxQueued) {
                    diagMaxQueued = queued;
                }
                int pending = LiGetPendingVideoFrames();
                if (pending > diagMaxPending) {
                    diagMaxPending = pending;
                }
            }
#endif
        }

        if (!receivedDataFromPeer) {
            receivedDataFromPeer = true;
            Limelog("Received first video packet after %d ms\n", waitingForVideoMs);

            firstDataTimeMs = PltGetMillis();
        }

#ifndef LC_FUZZING
        if (!receivedFullFrame) {
            if (PltGetMillis() - firstDataTimeMs >= FIRST_FRAME_TIMEOUT_SEC * 1000) {
                Limelog("Terminating connection due to lack of a successful video frame\n");
                ListenerCallbacks.connectionTerminated(ML_ERROR_NO_VIDEO_FRAME);
                break;
            }
        }
#endif

        if (err < minSize) {
            // Runt packet (arrived: not missing)
            skippedSinceSeq++;
            continue;
        }

        // Decrypt the packet into the buffer if encryption is enabled
        if (encrypted) {
            PENC_VIDEO_HEADER encHeader = (PENC_VIDEO_HEADER)encryptedBuffer;

            // If this frame is below our current frame number, discard it before decryption
            // to save CPU cycles decrypting FEC shards for a frame we already reassembled.
            //
            // Since this is happening _before_ decryption, this packet is not trusted yet.
            // It's imperative that we do not mutate any state based on this packet until
            // after it has been decrypted successfully!
            //
            // It's possible for an attacker to inject a fake packet that has any value of
            // header fields they want, however this provides them no benefit because we will
            // simply drop said packet here (if it's below the current frame number) or it
            // will pass this check and be dropped during decryption (if contents is tampered)
            // or after decryption in the RTP queue (if it's a replay of a previous authentic
            // packet from the host).
            //
            // In short, an attacker spoofing this value via MITM or sending malicious values
            // impersonating the host from off-link doesn't gain them anything. If they have
            // a true MITM, they can DoS our connection by just dropping all our traffic, so
            // tampering with packets to fail this check doesn't accomplish anything they
            // couldn't already do. If they're not on-link, we just throw their malicious
            // traffic away (as mentioned in the paragraph above) and continue accepting
            // legitmate video traffic.
            if (encHeader->frameNumber && LE32(encHeader->frameNumber) < RtpvGetCurrentFrameNumber(&rtpQueue)) {
                // MoonCast: arrived, so not missing: the next sequence gap leaves it out
                skippedSinceSeq++;
                continue;
            }

            if (!PltDecryptMessage(decryptionCtx, ALGORITHM_AES_GCM, 0,
                                   (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                                   encHeader->iv, sizeof(encHeader->iv),
                                   encHeader->tag, sizeof(encHeader->tag),
                                   ((unsigned char*)(encHeader + 1)), err - sizeof(ENC_VIDEO_HEADER), // The ciphertext is after the header
                                   (unsigned char*)buffer, &err)) {
                Limelog("Failed to decrypt video packet!\n");
                skippedSinceSeq++;
                continue;
            }
        }

        // Convert fields to host byte-order
        packet = (PRTP_PACKET)&buffer[0];
        packet->sequenceNumber = BE16(packet->sequenceNumber);
        packet->timestamp = BE32(packet->timestamp);
        packet->ssrc = BE32(packet->ssrc);

        // gaps in the RTP sequence: packets that never reached this socket (always counted: the totals). Packets
        // that did arrive but were dropped before decryption (an old frame's FEC shards) aren't missing: as on
        // Android (moonlight-common-c 1bdb3ca, skippedSinceSeq), they come off the gap.
        if (diagHaveSeq) {
            uint16_t step = (uint16_t)(packet->sequenceNumber - diagLastSeq);
            if (step == 0 || step >= 0x8000) {
                diagSeqBack++;
            }
            else {
                uint32_t gap = step - 1;
                gap = gap > skippedSinceSeq ? gap - skippedSinceSeq : 0;
                diagSeqGaps += gap;
                totalMissing += gap;
                diagLastSeq = packet->sequenceNumber;
                skippedSinceSeq = 0;
            }
        }
        else {
            diagLastSeq = packet->sequenceNumber;
            diagHaveSeq = true;
            skippedSinceSeq = 0;
        }

        queueStatus = RtpvAddPacket(&rtpQueue, packet, err, (PRTPV_QUEUE_ENTRY)&buffer[decryptedSize]);

        if (receiveDiagnostics) {
            uint64_t workUs = PltGetMicroseconds() - diagRecvUs;
            if (workUs > diagMaxWorkUs) {
                diagMaxWorkUs = workUs;
            }
        }

        if (queueStatus == RTPF_RET_QUEUED) {
            // The queue owns the buffer
            buffer = NULL;
        }
    }

    if (buffer != NULL) {
        free(buffer);
    }

    if (encryptedBuffer != NULL) {
        free(encryptedBuffer);
    }
}

void notifyKeyFrameReceived(void) {
    // Remember that we got a full frame successfully
    receivedFullFrame = true;
}

// Decoder thread proc
static void VideoDecoderThreadProc(void* context) {
    while (!PltIsThreadInterrupted(&decoderThread)) {
        VIDEO_FRAME_HANDLE frameHandle;
        PDECODE_UNIT decodeUnit;

        if (!LiWaitForNextVideoFrame(&frameHandle, &decodeUnit)) {
            return;
        }

        LiCompleteVideoFrame(frameHandle, VideoCallbacks.submitDecodeUnit(decodeUnit));
    }
}

// Read the first frame of the video stream
int readFirstFrame(void) {
    // All that matters is that we close this socket.
    // This starts the flow of video on Gen 3 servers.

    closeSocket(firstFrameSocket);
    firstFrameSocket = INVALID_SOCKET;

    return 0;
}

// Terminate the video stream
void stopVideoStream(void) {
    if (!receivedDataFromPeer) {
        Limelog("No video traffic was ever received from the host!\n");
    }

    VideoCallbacks.stop();

    // Wake up client code that may be waiting on the decode unit queue
    stopVideoDepacketizer();

    PltInterruptThread(&udpPingThread);
    PltInterruptThread(&receiveThread);
    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        PltInterruptThread(&decoderThread);
    }

    if (firstFrameSocket != INVALID_SOCKET) {
        shutdownTcpSocket(firstFrameSocket);
    }

    PltJoinThread(&udpPingThread);
    PltJoinThread(&receiveThread);
    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        PltJoinThread(&decoderThread);
    }

    if (firstFrameSocket != INVALID_SOCKET) {
        closeSocket(firstFrameSocket);
        firstFrameSocket = INVALID_SOCKET;
    }
    if (rtpSocket != INVALID_SOCKET) {
        closeSocket(rtpSocket);
        rtpSocket = INVALID_SOCKET;
    }

    VideoCallbacks.cleanup();
}

// Start the video stream
int startVideoStream(void* rendererContext, int drFlags) {
    int err;

    firstFrameSocket = INVALID_SOCKET;

    // This must be called before the decoder thread starts submitting
    // decode units
    LC_ASSERT(NegotiatedVideoFormat != 0);
    err = VideoCallbacks.setup(NegotiatedVideoFormat, StreamConfig.width,
        StreamConfig.height, StreamConfig.fps, rendererContext, drFlags);
    if (err != 0) {
        return err;
    }

    rtpSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen,
                              RTP_RECV_PACKETS_BUFFERED * (StreamConfig.packetSize + MAX_RTP_HEADER_SIZE),
                              SOCK_QOS_TYPE_VIDEO);
    if (rtpSocket == INVALID_SOCKET) {
        VideoCallbacks.cleanup();
        return LastSocketError();
    }

    VideoCallbacks.start();

    err = PltCreateThread("VideoRecv", VideoReceiveThreadProc, NULL, &receiveThread);
    if (err != 0) {
        VideoCallbacks.stop();
        closeSocket(rtpSocket);
        VideoCallbacks.cleanup();
        return err;
    }

    if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
        err = PltCreateThread("VideoDec", VideoDecoderThreadProc, NULL, &decoderThread);
        if (err != 0) {
            VideoCallbacks.stop();
            PltInterruptThread(&receiveThread);
            PltJoinThread(&receiveThread);
            closeSocket(rtpSocket);
            VideoCallbacks.cleanup();
            return err;
        }
    }

    if (AppVersionQuad[0] == 3) {
        // Connect this socket to open port 47998 for our ping thread
        firstFrameSocket = connectTcpSocket(&RemoteAddr, AddrLen,
                                            FIRST_FRAME_PORT, FIRST_FRAME_TIMEOUT_SEC);
        if (firstFrameSocket == INVALID_SOCKET) {
            VideoCallbacks.stop();
            stopVideoDepacketizer();
            PltInterruptThread(&receiveThread);
            if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
                PltInterruptThread(&decoderThread);
            }
            PltJoinThread(&receiveThread);
            if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
                PltJoinThread(&decoderThread);
            }
            closeSocket(rtpSocket);
            VideoCallbacks.cleanup();
            return LastSocketError();
        }
    }

    // Start pinging before reading the first frame so GFE knows where
    // to send UDP data
    err = PltCreateThread("VideoPing", VideoPingThreadProc, NULL, &udpPingThread);
    if (err != 0) {
        VideoCallbacks.stop();
        stopVideoDepacketizer();
        PltInterruptThread(&receiveThread);
        if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
            PltInterruptThread(&decoderThread);
        }
        PltJoinThread(&receiveThread);
        if ((VideoCallbacks.capabilities & (CAPABILITY_DIRECT_SUBMIT | CAPABILITY_PULL_RENDERER)) == 0) {
            PltJoinThread(&decoderThread);
        }
        closeSocket(rtpSocket);
        if (firstFrameSocket != INVALID_SOCKET) {
            closeSocket(firstFrameSocket);
            firstFrameSocket = INVALID_SOCKET;
        }
        VideoCallbacks.cleanup();
        return err;
    }

    if (AppVersionQuad[0] == 3) {
        // Read the first frame to start the flow of video
        err = readFirstFrame();
        if (err != 0) {
            stopVideoStream();
            return err;
        }
    }

    return 0;
}

const RTP_VIDEO_STATS* LiGetRTPVideoStats(void) {
    return &rtpQueue.stats;
}
