/*
 * fido2 passthrough device.
 *
 * Copyright (c) 2022 Egor Duda <egor.duda@gmail.com>
 * Written by Egor Duda <egor.duda@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/qdev-properties-system.h"
#include "chardev/char-fe.h"
#include "hw/usb.h"
#include "migration/vmstate.h"

#include "u2f.h"

typedef struct FIDO2PassthruState FIDO2PassthruState;

struct FIDO2PassthruState {
    U2FKeyState base;

    /* Host device */
    CharBackend chr;

    uint8_t buf[U2FHID_PACKET_SIZE];
    uint8_t bufsize;
};

#define TYPE_FIDO2_PASSTHRU "fido2-passthru"
#define PASSTHRU_FIDO2_KEY(obj) \
    OBJECT_CHECK(FIDO2PassthruState, (obj), TYPE_FIDO2_PASSTHRU)

static void fido2_passthru_recv_from_guest(U2FKeyState *base,
                                    const uint8_t packet[U2FHID_PACKET_SIZE])
{
    FIDO2PassthruState *key = PASSTHRU_FIDO2_KEY(base);
    ssize_t written = qemu_chr_fe_write(&key->chr, packet, U2FHID_PACKET_SIZE);
    if (written != U2FHID_PACKET_SIZE) {
        error_report("%s: Bad written size (req 0x%zu, val 0x%zd)",
                     TYPE_FIDO2_PASSTHRU, (ssize_t)U2FHID_PACKET_SIZE, written);
    }
}

static void fido2_passthru_reset(FIDO2PassthruState *key)
{
    key->bufsize = 0;
}

static void fido2_passthru_unrealize(U2FKeyState *base)
{
    FIDO2PassthruState *key = PASSTHRU_FIDO2_KEY(base);
    fido2_passthru_reset(key);
}

static int can_receive(void *opaque)
{
    return 1;
}

static void receive(void *opaque, const uint8_t *buf, int size)
{
    FIDO2PassthruState *key = opaque;
    for (int i = 0; i < size; i++) {
        key->buf[key->bufsize] = buf[i];
        key->bufsize++;
        if (key->bufsize >= U2FHID_PACKET_SIZE) {
                u2f_send_to_guest(&key->base, key->buf);
                key->bufsize = 0;
        }
    }
}

static void chr_event(void *opaque, QEMUChrEvent event)
{
}

static void fido2_passthru_realize(U2FKeyState *base, Error **errp)
{
    FIDO2PassthruState *key = PASSTHRU_FIDO2_KEY(base);

    if (!qemu_chr_fe_backend_connected(&key->chr)) {
        error_setg(errp, "fido2-passthru device requires chardev attribute");
        return;
    }

    qemu_chr_fe_set_handlers(&key->chr, can_receive, receive,
                             chr_event, NULL, key, NULL, true);

    fido2_passthru_reset(key);
}

static int fido2_passthru_post_load(void *opaque, int version_id)
{
    FIDO2PassthruState *key = opaque;
    fido2_passthru_reset(key);
    return 0;
}

static const VMStateDescription fido2_passthru_vmstate = {
    .name = "fido2-key-passthru",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = fido2_passthru_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_U2F_KEY(base, FIDO2PassthruState),
        VMSTATE_END_OF_LIST()
    }
};

static Property fido2_passthru_properties[] = {
    DEFINE_PROP_CHR("chardev", FIDO2PassthruState, chr),
    DEFINE_PROP_END_OF_LIST(),
};

static void fido2_passthru_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    U2FKeyClass *kc = U2F_KEY_CLASS(klass);

    kc->realize = fido2_passthru_realize;
    kc->unrealize = fido2_passthru_unrealize;
    kc->recv_from_guest = fido2_passthru_recv_from_guest;
    dc->desc = "QEMU FIDO2 passthrough key";
    dc->vmsd = &fido2_passthru_vmstate;
    device_class_set_props(dc, fido2_passthru_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo fido2_key_passthru_info = {
    .name = TYPE_FIDO2_PASSTHRU,
    .parent = TYPE_U2F_KEY,
    .instance_size = sizeof(FIDO2PassthruState),
    .class_init = fido2_passthru_class_init
};

static void fido2_key_passthru_register_types(void)
{
    type_register_static(&fido2_key_passthru_info);
}

type_init(fido2_key_passthru_register_types)
