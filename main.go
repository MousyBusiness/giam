package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type HumanReadableDuration string

// Add these methods to implement pflag.Value interface
func (d *HumanReadableDuration) String() string {
	return string(*d)
}

func (d *HumanReadableDuration) Set(value string) error {
	*d = HumanReadableDuration(value)
	_, err := d.Parse()
	return err
}

func (d *HumanReadableDuration) Type() string {
	return "duration"
}

func (d HumanReadableDuration) Parse() (dur time.Duration, err error) {
	numStr := d[:len(d)-1]
	num, err := strconv.Atoi(string(numStr))
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: use <num>s(seconds), <num>m(minutes), <num>h(hours), <num>d(days), or <num>w(weeks), e.g. 5m for 5 minutes")
	}
	period := d[len(d)-1]
	// Parse duration strings like "1d", "1w", "1m"
	switch period {
	case 's':
		dur = time.Second * time.Duration(num)
	case 'm':
		dur = time.Minute * time.Duration(num)
	case 'h':
		dur = time.Hour * time.Duration(num)
	case 'd':
		dur = time.Hour * 24 * time.Duration(num)
	case 'w':
		dur = time.Hour * 24 * 7 * time.Duration(num)
	default:
		return 0, fmt.Errorf("invalid duration format: use d(days), w(weeks), or m(months)")
	}
	return dur, nil
}

func main() {
	var duration HumanReadableDuration
	var member string
	var role string
	var projectID string
	rootCmd := &cobra.Command{
		Use:   "giam",
		Short: "Google IAM permission manager",
		Long:  `A CLI tool to manage temporary IAM permissions in Google Cloud Platform`,
	}

	grantCmd := &cobra.Command{
		Use:   "grant",
		Short: "Grant IAM permissions to a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			// If projectID is not set, try to get it from the config file
			if projectID == "" {
				projectID = viper.GetString("project")
				if projectID == "" {
					return fmt.Errorf("project ID is required")
				}
			}

			parsedDuration, err := duration.Parse()
			if err != nil {
				return err
			}

			fmt.Printf("About to grant role %s to %s for duration: %s\n", role, member, parsedDuration)
			fmt.Print("Do you want to continue? [y/N]: ")
			var response string
			fmt.Scanln(&response)

			if strings.ToLower(response) != "y" {
				return fmt.Errorf("operation cancelled by user")
			}

			// Check for existing policy
			checkCmd := exec.Command("gcloud", "projects", "get-iam-policy", projectID, "--format=json")
			output, err := checkCmd.Output()
			if err != nil {
				return fmt.Errorf("failed to get IAM policy: %v", err)
			}

			var policy struct {
				Bindings []struct {
					Members   []string `json:"members"`
					Role      string   `json:"role"`
					Condition struct {
						Title string `json:"title"`
					} `json:"condition,omitempty"`
				} `json:"bindings"`
			}

			if err := json.Unmarshal(output, &policy); err != nil {
				return fmt.Errorf("failed to parse IAM policy: %v", err)
			}

			memberStr := "user:" + member
			for _, binding := range policy.Bindings {
				if binding.Role == role {
					for _, existingMember := range binding.Members {
						if existingMember == memberStr {
							// Found existing binding
							fmt.Printf("Found existing binding for %s with role %s\n", member, role)
							if binding.Condition.Title != "" {
								fmt.Printf("The binding has condition with title: %s\n", binding.Condition.Title)
							}

							fmt.Print("Do you want to remove the existing binding before adding new one? [y/N]: ")
							var response string
							fmt.Scanln(&response)

							if strings.ToLower(response) == "y" {
								removeCmd := exec.Command("gcloud", "projects", "remove-iam-policy-binding",
									projectID,
									"--member", memberStr,
									"--role", role,
									"--all")

								removeCmd.Stderr = os.Stderr
								if err := removeCmd.Run(); err != nil {
									return fmt.Errorf("failed to remove existing binding: %v", err)
								}
								fmt.Printf("Removed existing binding for %s with role %s\n", member, role)
							}
							break
						}
					}
				}
			}

			expireTime := time.Now().Add(parsedDuration)
			condition := fmt.Sprintf("request.time < timestamp('%s')", expireTime.Format(time.RFC3339))
			conditionTitle := fmt.Sprintf("expires_%s", expireTime.Format("2006_01_02_15:04:05_MST"))

			// Construct gcloud command
			a := []string{
				"projects",
				"add-iam-policy-binding",
				projectID,
				"--member",
				"user:" + member,
				"--role", role,
				"--condition", fmt.Sprintf("expression=%s,title=%s", condition, conditionTitle),
			}

			c := exec.Command("gcloud", a...)
			c.Stderr = os.Stderr

			if err := c.Run(); err != nil {
				return fmt.Errorf("failed to execute gcloud command: %v", err)
			}

			fmt.Printf("Granted role %s to %s until %s\n", role, member, expireTime.Format(time.RFC3339))
			return nil
		},
	}

	// Add flags to grant command
	grantCmd.Flags().VarP(&duration, "duration", "d", "Duration for the permission (e.g., 1s, 1m, 1h, 1d, 1w)")
	grantCmd.Flags().StringVarP(&member, "member", "m", "", "Member to grant permission to (e.g., user@example.com)")
	grantCmd.Flags().StringVarP(&role, "role", "r", "", "Role to grant (e.g., roles/run.invoker)")
	grantCmd.Flags().StringVarP(&projectID, "project", "p", "", "Project ID (e.g., my-project-id)")
	grantCmd.MarkFlagRequired("duration")
	grantCmd.MarkFlagRequired("member")
	grantCmd.MarkFlagRequired("role")

	rootCmd.AddCommand(grantCmd)

	// Initialize viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.giam")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Error reading config file: %v\n", err)
			os.Exit(1)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
