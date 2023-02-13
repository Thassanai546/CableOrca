import time
import speedtest

def get_speed_mbs():
    output = ""
    output += "Network Speed Test Complete!\n\n"

    start_time = time.time()
    my_test = speedtest.Speedtest()
    my_test.get_best_server()

    # Change to mbs
    download_speed = my_test.download()/1000000
    upload_speed = my_test.upload()/1000000

    output += "Download Speed: {} Mbs\n".format("%.2f" % download_speed)
    output += "Upload Speed: {} Mbs\n".format("%.2f" % upload_speed)

    end_time = time.time()
    elapsed_time = end_time - start_time

    output += "Analysis completed in {} seconds\n".format("%.2f" % elapsed_time)
    url_to_result = my_test.results.share()

    """
    downloadtime = get_download_time(my_test.download())
    downloadtime = round(downloadtime, 2)
    output += "With this speed 1gb file could be downloaded in {} seconds.".format(downloadtime)
    """
    return url_to_result, output

def get_download_time(download_speed):
    # 1 GB is equal to 1,073,741,824 bytes
    one_gb_bytes = 1073741824

    # calculate the time it takes to download the file
    download_time = one_gb_bytes / download_speed
    return download_time