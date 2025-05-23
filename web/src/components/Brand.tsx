import React, { Fragment } from "react";

import { Divider, Link, Theme } from "@mui/material";
import { grey } from "@mui/material/colors";
import Grid from "@mui/material/Grid";
import { useTranslation } from "react-i18next";
import { makeStyles } from "tss-react/mui";

import PrivacyPolicyLink from "@components/PrivacyPolicyLink";
import { EncodedName, EncodedURL } from "@constants/constants";
import { getPrivacyPolicyEnabled } from "@utils/Configuration";

export interface Props {}

const Brand = function (props: Props) {
    const { t: translate } = useTranslation();

    const { classes } = useStyles();
    const privacyEnabled = getPrivacyPolicyEnabled();

    return (
        <Grid container size={{ xs: 12 }} alignItems="center" justifyContent="center">
            <Grid size={{ xs: 4 }}>
                <Link
                    href={atob(String.fromCharCode(...EncodedURL))}
                    target="_blank"
                    underline="hover"
                    className={classes.links}
                >
                    {translate("Powered by {{authelia}}", { authelia: atob(String.fromCharCode(...EncodedName)) })}
                </Link>
            </Grid>
            {privacyEnabled ? (
                <Fragment>
                    <Divider orientation="vertical" flexItem variant="middle" />
                    <Grid size={{ xs: 4 }}>
                        <PrivacyPolicyLink className={classes.links} />
                    </Grid>
                </Fragment>
            ) : null}
        </Grid>
    );
};

const useStyles = makeStyles()((theme: Theme) => ({
    links: {
        fontSize: "0.7rem",
        color: grey[500],
    },
}));

export default Brand;
