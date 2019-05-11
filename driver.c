#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/interrupt.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

struct tasklet_struct my_t;

void tasklet_func(unsigned long data) {
    printk(KERN_INFO "tasklet function is executed");
}

void post_init(void) {

    tasklet_init(&my_t, tasklet_func, 123);

}

static int pen_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    printk(KERN_INFO "Pen drive (%04X:%04X) plugged\n", id->idVendor,
            id->idProduct);

    tasklet_schedule(&my_t);

    return 0;
}

static void pen_disconnect(struct usb_interface *interface)
{
    printk(KERN_INFO "Pen drive removed\n");
}

static struct usb_device_id pen_table[] =
        {
                { USB_DEVICE(0x1d6b, 0x0002) },
                {} /* Terminating entry */
        };
MODULE_DEVICE_TABLE (usb, pen_table);

static struct usb_driver pen_driver =
        {
                .name = "pen_driver",
                .id_table = pen_table,
                .probe = pen_probe,
                .disconnect = pen_disconnect,
        };

static int __init pen_init(void)
{
    post_init();
    return usb_register_driver(&pen_driver, THIS_MODULE, KBUILD_MODNAME);
}

static void __exit pen_exit(void)
{
//    usb_deregister(&pen_driver);
}

module_init(pen_init);
module_exit(pen_exit);